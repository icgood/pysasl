# type: ignore

from invoke import task, Collection
from invoke.tasks import call

from .check import check_import


@task(check_import)
def mypy(ctx):
    """Run the mypy type checker."""
    ctx.run('mypy')


@task(check_import)
def pyright(ctx, verifytypes=False):
    """Run the pyright type checker."""
    if verifytypes:
        ctx.run('pyright --verifytypes pysasl')
    else:
        ctx.run('pyright')


@task(mypy, pyright, call(pyright, verifytypes=True))
def all(ctx):
    """Run all the type checker tools."""
    del ctx


ns = Collection(mypy, pyright)
ns.add_task(all, default=True)
