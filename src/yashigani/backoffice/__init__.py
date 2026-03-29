"""Yashigani Backoffice — Admin control plane."""
from yashigani.backoffice.app import create_backoffice_app
from yashigani.backoffice.state import backoffice_state, BackofficeState

__all__ = ["create_backoffice_app", "backoffice_state", "BackofficeState"]
