from flask import (
    Flask,
    render_template,
    request,
    session,
    redirect,
    url_for,
    jsonify,
    send_file,
    flash
)
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
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
import secrets
from werkzeug.utils import secure_filename
from src.tools.logging import LOGGER, getLogger
from src.tools.user import User
from datetime import timedelta, datetime
from pathlib import Path
from functools import wraps

# CONFIGURATION
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config["UPLOAD_PATH"] = "temp"
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "index"

connection_cache = {}
vm_cache = {}
vm_file_cache = {}

OUTPUT_DIR = "/output"
VCENTER = os.environ.get("vcenter", "")


# --- Check Admin Decorator ---
def is_vcenter_connected(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        LOGGER.info("[is_vcenter_connected]")
        if not check_connection(si=connection_cache.get(current_user.id)):
            connection_cache[current_user.id] = SmartConnect(
            host=current_user.host,
            user=current_user.username,
            pwd=current_user.password,
            disableSslCertValidation=True,
        )
        atexit.register(Disconnect, connection_cache[current_user.id])
        return func(*args, **kwargs)
    return decorated_view

@app.errorhandler(404)
def not_found(e):
    return redirect(url_for("authenticated"))


@app.errorhandler(401)
def not_authorized(e):
    return redirect(url_for("authenticated"))


@app.errorhandler(403)
def page_forbidden(e):
    return redirect(url_for("authenticated"))


@app.errorhandler(500)
def internal_server_error(e):
    return redirect(url_for("authenticated"))


@app.route("/index", methods=["GET"])
def index():
    try:
        return render_template("index.html")
        #return redirect(url_for("authenticated"))
    except Exception as ex:
        LOGGER.error(f"[index] {ex}")
        return render_template("index.html", errors=str(ex))
        #return redirect(url_for("log_out"))

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
        user = User(
            user_id=str(uuid.uuid4()),
            username=str(args.get("user")),
            password=str(args.get("password")),
            host=str(args.get("host")),
        )
        session["user_data"] = {
            "id": user.id,
            "username": user.username,
            "host": user.host,
            "password": user.password,
            "list_vms": dict()
        }
        login_user(user, remember=True)  # connection flasklogin
        
        # Générer un identifiant unique pour la session
        #session_id = str(uuid.uuid4())
        # Stocker l'instance de connexion dans le cache
        connection_cache[user.id] = service_instance

        #session["session_id"] = session_id
        #session["connect"] = args.copy()
        #session["is_connected"] = True
        return redirect(url_for("authenticated"))
    except Exception as ex:
        #session["is_connected"] = False
        LOGGER.error(f"[authenticate] {ex}")
        return render_template(
            "index.html",
            errors="Cannot complete login due to an incorrect user name or password.",
        )

@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = session.get("user_data")
        if user_data and str(user_data.get("id", "")) == user_id:
            return User(
                user_id=user_data.get("id"),
                username=user_data.get("username"),
                password=user_data.get("password"),
                host=user_data.get("host"),
            )
    except Exception as ex:
        LOGGER.error(f"[load_user] {ex}")
        return None


@app.route("/", methods=["GET"])
@login_required
@is_vcenter_connected
def authenticated():
    try:
        current_user.list_vms = parse_service_instance(connection_cache.get(current_user.id))
        return render_template("connected.html", data=current_user.list_vms)
    except Exception as ex:
        LOGGER.error(f"[authenticated] {ex}")
        return redirect(url_for("log_out"))


@app.route("/logout", methods=["GET", "POST"])
@login_required
def log_out():
    Disconnect(connection_cache.get(current_user.id))
    connection_cache.pop(current_user.id, None)
    logout_user()
    session.clear()
    return render_template(
        "index.html", logout_msg="Utilisateur déconnecté avec succès"
    )


@app.route("/vminfos", methods=["GET"])
@login_required
@is_vcenter_connected
def get_vm_infos():
    try:
        vmName = request.args.get("vm", "")
        content = connection_cache.get(current_user.id).RetrieveContent()
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
@login_required
@is_vcenter_connected
def start_vm():
    try:
        vmName = request.form.get("vm_name", "")
        content = connection_cache.get(current_user.id).RetrieveContent()
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
@login_required
@is_vcenter_connected
def stop_vm():
    try:
        vmName = request.form.get("vm_name", "")
        content = connection_cache.get(current_user.id).RetrieveContent()
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
@login_required
@is_vcenter_connected
def upload_vm():
    try:
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

        content = connection_cache.get(current_user.id).RetrieveContent()
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
@login_required
@is_vcenter_connected
def refresh_list_files_vm():
    try:
        vm_name = request.form.get("vm_name", "")
        vm_login = request.form.get("vm_login", "")
        vm_password = request.form.get("vm_password", "")
        vm_path = request.form.get("vm_path", "")

        content = connection_cache.get(current_user.id).RetrieveContent()
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
@login_required
@is_vcenter_connected
def logout_vm():
    # Destruction de la session de la VM
    session.pop("vm", default=None)
    session.pop("vm_username", default=None)
    vm_cache.pop(session.get("session_id", ""))
    vm_file_cache.pop(session.get("id_session", ""))

    return redirect(url_for("authenticated"))


@app.route("/refresh", methods=["GET"])
@login_required
@is_vcenter_connected
def refresh():
    try:
        current_user.list_vms = parse_service_instance(
            connection_cache[current_user.id]
        )
        return render_template("connected.html", data=current_user.list_vms)
    except Exception as ex:
        LOGGER.error(f"[ERROR refresh] {ex}")
        _msg = str(ex)
        if ".fault." in _msg:
            _msg = ex.msg
        return jsonify(msg=str(_msg), res={}, error=True)


@app.route("/vm/download", methods=["GET", "POST"])
@login_required
@is_vcenter_connected
def download_file():
    try:
        if request.method == "POST":
            vm_name = request.form.get("vm_name", "")
            vm_login = request.form.get("vm_login", "")
            vm_password = request.form.get("vm_password", "")
            vm_path = request.form.get("vm_path", "")
            vm_download_file = request.form.get("vm_download_file", "")
            content = connection_cache.get(current_user.id).RetrieveContent()
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
@login_required
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
