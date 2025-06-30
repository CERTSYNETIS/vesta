from flask import (
    Flask,
    render_template,
    request,
    session,
    redirect,
    url_for,
    jsonify,
    send_file,
)
import ssl
import os
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
from src.tools.fonctions import (
    list_file_in_vm,
    parse_service_instance,
    get_vm_info,
    check_connection,
)
import src.tools.pchelper as pchelper
import atexit
import uuid
import re
import requests
from werkzeug.utils import secure_filename
from src.tools.logging import LOGGER, getLogger
from datetime import timedelta, datetime
from pathlib import Path

# CONFIGURATION
app = Flask(__name__)

app.secret_key = os.environ.get("secret_key", "s3cr3t")
app.config["UPLOAD_PATH"] = "temp"

connection_cache = {}
vm_cache = {}
vm_file_cache = {}

OUTPUT_DIR = "/output"
VCENTER = os.environ.get("vcenter", "")


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=24)


# CODE
@app.route("/", methods=["GET"])
def index():
    try:
        if session.get("session_id", None):
            if not connection_cache.get(session.get("session_id", ""), None):
                raise Exception("No session_id in connections")
        else:
            raise Exception("No session_id in session")
        return redirect(url_for("authenticated"))
    except Exception as ex:
        LOGGER.error(f"[index] {ex}")
        return redirect(url_for("log_out"))


def is_connected() -> bool:
    try:
        if session.get("session_id", None):
            if not connection_cache.get(session.get("session_id", ""), None):
                raise Exception("No session_id in connections")
            else:
                if not check_connection(
                    si=connection_cache.get(session.get("session_id"))
                ):
                    raise Exception("Not connected to vcenter")
        else:
            raise Exception("No session_id in session")
        return True
    except Exception as ex:
        LOGGER.error(f"[is_connected] {ex}")
        return False


@app.route("/auth", methods=["GET", "POST"])
def authenticate():
    try:
        if request.method == "GET":
            return redirect(url_for("index"))
        args = dict()
        args["host"] = VCENTER
        args["disable_ssl_verification"] = True
        args["user"] = request.form.get("login_username", "")
        args["password"] = request.form.get("login_password", "")
        LOGGER.info(f"[authenticate] Connecting to {VCENTER}...")
        service_instance = SmartConnect(
            host=args.get("host"),
            user=args.get("user"),
            pwd=args.get("password"),
            disableSslCertValidation=args.get("disable_ssl_verification"),
        )
        atexit.register(Disconnect, service_instance)
        # Générer un identifiant unique pour la session
        session_id = str(uuid.uuid4())
        # Stocker l'instance de connexion dans le cache
        connection_cache[session_id] = service_instance

        session["session_id"] = session_id
        session["connect"] = args.copy()
        session["is_connected"] = True
        session["list_vms"] = dict()

        return redirect(url_for("authenticated"))

    except Exception as ex:
        session["is_connected"] = False
        LOGGER.error(f"[authenticate] {ex}")
        return render_template(
            "index.html",
            errors="Cannot complete login due to an incorrect user name or password.",
        )


@app.route("/authenticated", methods=["GET"])
def authenticated():
    try:
        if not is_connected():
            raise Exception("Not connected to vcenter instance")
        # session["list_vms"] = fetch_vm_from_file(
        #     connection_cache.get(session.get("session_id"))
        # )
        session["list_vms"] = parse_service_instance(
            connection_cache.get(session.get("session_id"))
        )
        return render_template("connected.html", data=session["list_vms"])

    except Exception as ex:
        LOGGER.error(f"[authenticated] {ex}")
        return redirect(url_for("log_out"))


@app.route("/logout", methods=["GET", "POST"])
def log_out():
    session_id = session.get("session_id", "")
    if session_id in connection_cache:
        try:
            # Récupérer et déconnecter l'instance de connexion
            service_instance = connection_cache.pop(session_id, None)
            if service_instance:
                Disconnect(service_instance)
        except Exception as error:
            LOGGER.error(f"[logout] {error}")

    session.pop("username", default=None)
    session.pop("vm", default=None)
    session.pop("vm_username", default=None)
    session.pop("session_id", default=None)
    session.pop("connect", default=None)
    session.pop("is_connected", default=None)

    return render_template(
        "index.html", logout_msg="Utilisateur déconnecté avec succès"
    )


@app.route("/vminfos", methods=["GET"])
def get_vm_infos():
    try:
        if not is_connected():
            raise Exception("Not connected to vcenter instance")
        vmName = request.args.get("vm", "")
        content = connection_cache.get(session.get("session_id")).RetrieveContent()
        vm = pchelper.get_obj(content, [vim.VirtualMachine], vmName)
        vm_infos = get_vm_info(virtual_machine=vm)
        return jsonify(vminfos=vm_infos)

    except Exception as ex:
        LOGGER.error(f"[get_vm_infos] {ex}")
        _msg = str(ex)
        if ".fault." in _msg:
            _msg = ex.msg
        return jsonify(msg=str(_msg), res={}, error=True)


@app.route("/startvm", methods=["POST"])
def start_vm():
    try:
        if not is_connected():
            raise Exception("Not connected to vcenter instance")
        vmName = request.form.get("vm_name", "")
        content = connection_cache.get(session.get("session_id")).RetrieveContent()
        vm = pchelper.get_obj(content, [vim.VirtualMachine], vmName)
        vm.PowerOn()
        return jsonify(powerstatus="started", error=False)

    except Exception as ex:
        LOGGER.error(f"[start_vm] {ex}")
        _msg = str(ex)
        if ".fault." in _msg:
            _msg = ex.msg
        return jsonify(msg=str(_msg), res={}, error=True)


@app.route("/stopvm", methods=["POST"])
def stop_vm():
    try:
        if not is_connected():
            raise Exception("Not connected to vcenter instance")
        vmName = request.form.get("vm_name", "")
        content = connection_cache.get(session.get("session_id")).RetrieveContent()
        vm = pchelper.get_obj(content, [vim.VirtualMachine], vmName)
        vm.PowerOff()
        return jsonify(powerstatus="Powered Off", error=False)

    except Exception as ex:
        LOGGER.error(f"[stop_vm] {ex}")
        _msg = str(ex)
        if ".fault." in _msg:
            _msg = ex.msg
        return jsonify(msg=str(_msg), res={}, error=True)


@app.route("/vm/upload", methods=["POST"])
def upload_vm():
    try:
        if not is_connected():
            raise Exception("Not connected to vcenter instance")
        vm_name = request.form.get("vm_name", "")
        vm_login = request.form.get("vm_login", "")
        vm_password = request.form.get("vm_password", "")
        vm_path = request.form.get("vm_path", "")
        vm_upload_file = None
        vm_upload_file_filename = ""
        vm_upload_file_data = None
        try:
            if "vm_upload_file" in request.files:
                if request.files["vm_upload_file"]:
                    vm_upload_file = request.files["vm_upload_file"]
                    vm_upload_file_filename = secure_filename(vm_upload_file.filename)
                    vm_upload_file_data = vm_upload_file.read()
        except Exception as file_error:
            LOGGER.error(f"[upload_vm] file upload error: {file_error}")
            raise Exception("Upload file error")

        content = connection_cache[session.get("session_id")].RetrieveContent()
        vm = pchelper.get_obj(content, [vim.VirtualMachine], vm_name)
        vm_infos = get_vm_info(virtual_machine=vm)
        if (
            "toolsNotInstalled" in vm_infos["tools_version"]
            or "toolsNotRunning" in vm_infos["tools_version"]
        ):
            raise Exception("Tools not installed or not running in VM")

        if "windows" in vm_infos["guest"].lower():
            vm_path = f"{vm_path}\\{vm_upload_file_filename}"
        elif "linux" in vm_infos["guest"].lower():
            vm_path = f"{vm_path}/{vm_upload_file_filename}"

        # connexion à la VM
        creds = vim.vm.guest.NamePasswordAuthentication(
            username=vm_login,
            password=vm_password,
        )
        session["vm"] = vm_name
        session["vm_login"] = vm_login
        """ vm_files = list_file_in_vm(
            content, vm, vm_cache[session.get("session_id")], vm_path
        )
        vm_file_cache[session.get("id_session")] = vm_files """
        file_attribute = vim.vm.guest.FileManager.FileAttributes()
        url = content.guestOperationsManager.fileManager.InitiateFileTransferToGuest(
            vm,
            creds,
            vm_path,
            file_attribute,
            len(vm_upload_file_data),
            True,
        )
        url = re.sub(r"^https://\*:", "https://" + vm_name + ":", url)
        resp = requests.put(url, data=vm_upload_file_data, verify=False)
        if not resp.status_code == 200:
            LOGGER.error("[upload_vm] Error while uploading file")
        else:
            LOGGER.info("[upload_vm] Successfully uploaded file")
        return jsonify(msg="Upload successful", res={})

    except Exception as ex:
        LOGGER.error(f"[upload_vm] {ex}")
        _msg = str(ex)
        if ".fault." in _msg:
            _msg = ex.msg
        return jsonify(msg=str(_msg), res={}, error=True)


@app.route("/vm/refresh", methods=["POST"])
def refresh_list_files_vm():
    try:
        if not is_connected():
            raise Exception("Not connected to vcenter instance")
        vm_name = request.form.get("vm_name", "")
        vm_login = request.form.get("vm_login", "")
        vm_password = request.form.get("vm_password", "")
        vm_path = request.form.get("vm_path", "")

        content = connection_cache[session.get("session_id")].RetrieveContent()
        vm = pchelper.get_obj(content, [vim.VirtualMachine], vm_name)
        vm_infos = get_vm_info(virtual_machine=vm)
        if (
            "toolsNotInstalled" in vm_infos["tools_version"]
            or "toolsNotRunning" in vm_infos["tools_version"]
        ):
            raise Exception("Tools not installed or not running in VM")
        # connexion à la VM
        creds = vim.vm.guest.NamePasswordAuthentication(
            username=vm_login,
            password=vm_password,
        )
        session["vm"] = vm_name
        session["vm_login"] = vm_login
        vm_files = list_file_in_vm(content, vm, creds, vm_path)
        vm_file_cache[session.get("id_session")] = vm_files

        return jsonify(msg="refresh successful", files=vm_files)

    except Exception as ex:
        LOGGER.error(f"[refresh_list_files_vm] {ex}")
        _msg = str(ex)
        if ".fault." in _msg:
            _msg = ex.msg
        return jsonify(msg=str(_msg), res={}, error=True)


@app.route("/vm/logout", methods=["GET"])
def logout_vm():
    # Destruction de la session de la VM
    session.pop("vm", default=None)
    session.pop("vm_username", default=None)
    vm_cache.pop(session.get("session_id", ""))
    vm_file_cache.pop(session.get("id_session", ""))

    return redirect(url_for("authenticated"))


@app.route("/refresh", methods=["GET"])
def refresh():
    try:
        if not is_connected():
            raise Exception("Not connected to vcenter instance")

        session["list_vms"] = parse_service_instance(
            connection_cache[session.get("session_id")]
        )
        return render_template("connected.html", data=session["list_vms"])
    except Exception as ex:
        LOGGER.error(f"[ERROR refresh] {ex}")
        _msg = str(ex)
        if ".fault." in _msg:
            _msg = ex.msg
        return jsonify(msg=str(_msg), res={}, error=True)


@app.route("/vm/download", methods=["GET", "POST"])
def download_file():
    try:
        if request.method == "POST":
            if not is_connected():
                raise Exception("Not connected to vcenter instance")
            vm_name = request.form.get("vm_name", "")
            vm_login = request.form.get("vm_login", "")
            vm_password = request.form.get("vm_password", "")
            vm_path = request.form.get("vm_path", "")
            vm_download_file = request.form.get("vm_download_file", "")
            content = connection_cache[session.get("session_id")].RetrieveContent()
            vm = pchelper.get_obj(content, [vim.VirtualMachine], vm_name)
            vm_infos = get_vm_info(virtual_machine=vm)
            if (
                "toolsNotInstalled" in vm_infos["tools_version"]
                or "toolsNotRunning" in vm_infos["tools_version"]
            ):
                raise Exception("Tools not installed or not running in VM")
            if "windows" in vm_infos["guest"].lower():
                vm_path = f"{vm_path}\\{vm_download_file}"
            elif "linux" in vm_infos["guest"].lower():
                vm_path = f"{vm_path}/{vm_download_file}"

            creds = vim.vm.guest.NamePasswordAuthentication(
                username=vm_login,
                password=vm_password,
            )
            fti = content.guestOperationsManager.fileManager.InitiateFileTransferFromGuest(
                vm,
                creds,
                vm_path,
            )
            resp = requests.get(fti.url, verify=False)
            if not resp.status_code == 200:
                raise Exception("Error while downloading file")
            else:
                LOGGER.info("[download_file] Successfully downloaded file")
            with open(f"{OUTPUT_DIR}/{vm_download_file}", "wb") as dlfile:
                dlfile.write(resp.content)

            # buffer = BytesIO()
            # buffer.write(resp.content)
            # buffer.seek(0)

            return jsonify(
                msg="File ready to download.",
                res={"filename": vm_download_file},
            )
        elif request.method == "GET":
            filename = request.args.get("filename", None)
            filepath = os.path.join(OUTPUT_DIR, filename)
            if os.path.isfile(filepath):
                return send_file(
                    path_or_file=filepath,  # buffer,
                    as_attachment=True,
                    download_name=filename,
                )
            else:
                raise Exception(f"file not found: {filename}")
        else:
            raise Exception("Method not implemented")

    except Exception as ex:
        LOGGER.error(f"[download_file] {ex}")
        _msg = str(ex)
        if ".fault." in _msg:
            _msg = ex.msg
        return jsonify(msg=str(_msg), res={}, error=True)


def directory_exists(dir: str) -> bool:
    try:
        if Path(dir).is_dir():
            return True
        else:
            return False
    except Exception as ex:
        LOGGER.error(f"[directory_exists ERROR] {str(ex)}")
        return False


def list_directory(src: str, onlyfiles: bool = False, onlydirs: bool = False) -> list:
    if onlydirs:
        return [
            name for name in os.listdir(src) if os.path.isdir(os.path.join(src, name))
        ]
    elif onlyfiles:
        return [
            name for name in os.listdir(src) if os.path.isfile(os.path.join(src, name))
        ]
    else:
        return [name for name in os.listdir(src)]


@app.route("/vm/clear_downloaded_files", methods=["GET"])
def delete_files_in_output_directory() -> bool:
    """
    Delete downloadded files every 24h
    """
    try:
        if directory_exists(dir=OUTPUT_DIR):
            for file in list_directory(src=OUTPUT_DIR):
                _fpath = os.path.join(OUTPUT_DIR, file)
                if os.path.isfile(_fpath):
                    _ctime = datetime.fromtimestamp(os.path.getctime(_fpath))
                    _today = datetime.today()
                    if _today > _ctime + timedelta(days=1):
                        os.remove(_fpath)
                        LOGGER.info(
                            f"[delete_files_in_output_directory] Deleted file: {file}"
                        )
            return jsonify(mg="Delete OK", error=False)
        else:
            LOGGER.error("[delete_files_in_output_directory] Directory does not exist")
            return jsonify(mg="Directory does not exist", error=True)
    except Exception as ex:
        LOGGER.error(f"[delete_files_in_output_directory] {str(ex)}")
        return jsonify(mg=str(ex), error=True)


def main():
    print("======= Running on https://0.0.0.0:5000 =======")
    #os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.dirname(os.path.realpath(__file__))
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(
        os.path.join(path, "ssl", "cert.crt"),
        os.path.join(path, "ssl", "cert.key"),
    )
    app.static_url_path = "src/web/static"
    app.static_folder = "src/web/static"
    app.template_folder = "src/web/templates"
    app.logger.disabled = True
    log = getLogger("werkzeug")
    log.disabled = True
    app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=ssl_context)


if __name__ == "__main__":
    # wsgi.app.run()
    main()
    # main()
