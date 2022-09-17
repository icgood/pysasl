# type: ignore

from invoke import task, Collection

from .check import check_import


@task(check_import)
def mypy(ctx):
    """Run the mypy type checker."""
    ctx.run('mypy {} test'.format(ctx.package))


@task(check_import)
def pyright(ctx):
    """Run the pyright linter."""
    ctx.run('pyright {} test'.format(ctx.package))


@task(mypy, pyright)
def all(ctx):
    """Run all the type checker tools."""
    pass


ns = Collection(mypy, pyright)
ns.add_task(all, default=True)
