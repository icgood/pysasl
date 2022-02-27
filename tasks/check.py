# type: ignore

import os
from invoke import task, Collection
from invoke.exceptions import UnexpectedExit


class CheckImportFailed(UnexpectedExit):

    def __str__(self):
        return super().__str__() + '\nTry running:\n    $ invoke install\n'


@task
def check_import(ctx):
    """Check that the library can be imported."""
    if ctx.check_import:
        result = ctx.run('python -c "import {}"'.format(ctx.package),
                         hide=True, pty=False, warn=True)
        if not result.ok:
            raise CheckImportFailed(result)


@task
def check_venv(ctx):
    """Check that a virtualenv is active before installing."""
    if ctx.check_venv and os.getenv('VIRTUAL_ENV') is None:
        raise AssertionError('Must activate a virtualenv')


ns = Collection(check_venv)
ns.add_task(check_import, default=True)
