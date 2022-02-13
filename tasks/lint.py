# type: ignore

from invoke import task, Collection

from .check import check_import


@task(check_import)
def flake8(ctx):
    """Run the flake8 linter."""
    ctx.run('flake8 pysasl test *.py')


@task(check_import)
def bandit(ctx):
    """Run the bandit linter."""
    ctx.run('bandit -qr pysasl')


@task(flake8, bandit)
def all(ctx):
    """Run all linters."""
    del ctx


ns = Collection(flake8, bandit)
ns.add_task(all, default=True)
