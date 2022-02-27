# type: ignore

from invoke import task, Collection

from .check import check_import


@task(check_import)
def mypy(ctx):
    """Run the mypy type checker."""
    ctx.run('mypy {} test'.format(ctx.package))


@task(check_import)
def pyright_verifytypes(ctx):
    """Run the pyright --verifytypes linter."""
    ctx.run('pyright --verifytypes {}'.format(ctx.package))


@task(mypy, pyright_verifytypes)
def all(ctx):
    """Run all the type checker tools."""
    pass


ns = Collection(mypy, pyright_verifytypes)
ns.add_task(all, default=True)
