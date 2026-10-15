"""
GitGhost Main Entry Point.
Launches the interactive UI dashboard if run without arguments (e.g., double-clicked in Windows Explorer),
or dispatches to the CLI if command-line arguments are provided.
"""

import sys
from gitghost.cli import app
from gitghost.ui_window import launch_ui


def main():
    if len(sys.argv) == 1:
        launch_ui()
    else:
        app()


if __name__ == "__main__":
    main()
