"""
FoodShield integrated demo entry.

This wrapper keeps the historical command working:

    python -m project.integration_demo

It now runs the maintained attack/defense demo against an isolated temporary
database, so the repository's normal demo database is not modified.
"""

from project.tools.attack_demo import run_attack_demo


def run_system_integration_test():
    run_attack_demo(db_path=None)


if __name__ == "__main__":
    run_system_integration_test()
