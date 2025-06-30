from pyVmomi import vim
import functools
import time
import json
from src.tools.logging import LOGGER


def log(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        LOGGER.info(f"[CALLED] {func.__name__}")
        return func(*args, **kwargs)

    return wrapper


@log
def check_connection(si) -> bool:
    """
    Check if the instance is connected to vcenter
    """
    try:
        _session = si.content.sessionManager.currentSession.key
        if _session:
            LOGGER.info(f"[check_connection] session: {_session}")
            return True
        else:
            LOGGER.info("[check_connection] No session")
            return False
    except Exception as ex:
        LOGGER.error(f"[check_connection] {ex}")
        return False


@log
def parse_service_instance(si) -> dict:
    """
    Get VMs list from vcenter
    """
    try:
        list_vm = []
        content = si.RetrieveContent()
        object_view = content.viewManager.CreateContainerView(
            content.rootFolder, [], True
        )
        data = {}
        for obj in object_view.view:
            if isinstance(obj, vim.VirtualMachine):
                list_vm.append(obj.name)
                _folders = get_folder_path(obj)
                list_to_nested_dict(data=data, items=_folders)
        object_view.Destroy()
        # Sauvegarde des machines dans un fichier
        #with open("saved_vms.json", "w") as file:
        #    json.dump(data, file)

        return data
    except Exception as ex:
        LOGGER.error(f"[parse_service_instance] {ex}")
        return dict()


@log
def get_folder_path(obj) -> list:
    paths = []
    if isinstance(obj, vim.Folder):
        paths.append(obj.name)

    thisobj = obj
    paths.append(obj.name)
    while hasattr(thisobj, "parent"):
        thisobj = thisobj.parent
        try:
            moid = thisobj._moId
        except AttributeError:
            moid = None
        if moid in ["group-d1", "ha-folder-root"]:
            break
        if isinstance(thisobj, vim.Folder):
            paths.append(thisobj.name)
    paths.reverse()
    return paths


@log
def list_to_nested_dict(data: dict, items: list) -> dict:
    try:
        current_level = data
        for item in items[:-1]:  # Parcours jusqu'à l'avant-dernier élément
            if item not in current_level:
                current_level[item] = {}
            current_level = current_level[item]
        current_level[items[-1]] = {}  # Ajoute le dernier élément (fichier)
    except Exception as ie:  # ça veut dire que le dossier
        LOGGER.error(f"Item : {items}")
        LOGGER.error(f"Erreur :  {ie}")
    return data


@log
def fetch_vm_from_file(si):
    """fonction qui permet de récupérer l'arborescence des machines depuis un fichier
    Paramètres : Service instance
    Return : Liste des VMs en dictionnaire"""

    try:
        with open("saved_vms.json", "r") as file:
            list_vm = json.load(file)
    except FileNotFoundError as ex:
        LOGGER.error(f"[ERROR] - Fichier non trouvé {ex}")
        list_vm = parse_service_instance(si)

    return list_vm


@log
def list_file_in_vm(content, vm, creds, path):
    try:
        list_files = content.guestOperationsManager.fileManager.ListFilesInGuest(
            vm, creds, path
        )

        files = {}

        for file in list_files.files:
            if file.path != "." and file.path != "..":
                files[file.path] = file.type
        return files
    except Exception as ex:
        raise ex


def get_vm_info(virtual_machine) -> dict:
    vm_info = dict()
    summary = virtual_machine.summary

    vm_info["name"] = summary.config.name
    vm_info["template"] = summary.config.template
    vm_info["path"] = summary.config.vmPathName
    vm_info["guest"] = summary.config.guestFullName
    vm_info["instance_uuid"] = summary.config.instanceUuid
    vm_info["bios_uuid"] = summary.config.uuid
    vm_info["annotation"] = summary.config.annotation
    vm_info["state"] = summary.runtime.powerState
    vm_info["tools_version"] = ""
    vm_info["ip"] = ""
    if summary.guest is not None:
        vm_info["ip"] = summary.guest.ipAddress
        vm_info["tools_version"] = summary.guest.toolsStatus
    return vm_info
