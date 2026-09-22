import logging
from logging.config import dictConfig


def configure_logging(level: str) -> None:
    """Configure only our namespace, leaving the host's other loggers intact."""
    dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "standard": {
                    "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "standard",
                    "stream": "ext://sys.stderr",
                }
            },
            "loggers": {
                "ai_security_gateway": {
                    "handlers": ["console"],
                    "level": level,
                    "propagate": False,
                }
            },
        }
    )


logger = logging.getLogger("ai_security_gateway")
