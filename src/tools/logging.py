from logging import basicConfig, getLogger, Logger, FileHandler
from rich.console import Console
from rich.logging import RichHandler
from datetime import datetime

_time = datetime.today().strftime("%Y-%m-%d")
_fname = "logger.log"
basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%d-%m-%Y %H:%M:%S",
    level="DEBUG",
    handlers=[
        FileHandler(filename=_fname, mode="a"),
        RichHandler(console=Console(stderr=True)),
    ],
)


def get_logger(name: str) -> Logger:
    name = ".".join(["uploadvm"] + name.split("."))
    return getLogger(name)


LOGGER = get_logger(name="main")
