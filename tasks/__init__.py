# type: ignore

import inspect
import os
import os.path

if not hasattr(inspect, 'getargspec'):
    # https://github.com/pyinvoke/invoke/issues/833
    inspect.getargspec = inspect.getfullargspec

from invoke import task, Collection

from . import check, doc, lint, test, types

try:
    from shlex import join
except ImportError:  # Python < 3.8
    def join(args):
        return ' '.join(args)


@task
def clean(ctx, full=False):
    """Delete all the standard build and validate artifacts."""
    if full:
        ctx.run('git clean -dfX')
    else:
        anywhere = ['__pycache__']
        top_level = [
            '.coverage',
            '.mypy_cache',
            '.pytest_cache',
            'dist',
            'doc/build/']
        for name in anywhere:
            for path in [ctx.package, 'test']:
                subpaths = [os.path.join(subpath, name)
                            for subpath, dirs, names in os.walk(path)
                            if name in dirs or name in names]
                for subpath in subpaths:
                    ctx.run(join(['rm', '-rf', subpath]))
        for name in top_level:
            ctx.run(join(['rm', '-rf', name]))


@task
def install(ctx, dev=True, update=False):
    """Install the library and all development tools."""
    choice = 'dev' if dev else 'all'
    if update:
        ctx.run('pip install -U -r requirements-{}.txt'.format(choice))
    else:
        ctx.run('pip install -r requirements-{}.txt'.format(choice))


@task(test.all, types.all, lint.all)
def validate(ctx):
    """Run all tests, type checks, and linters."""
    pass


ns = Collection(clean, install)
ns.add_task(validate, default=True)
ns.add_collection(check)
ns.add_collection(test)
ns.add_collection(types)
ns.add_collection(lint)
ns.add_collection(doc)

ns.configure({
    'package': 'pysasl',
    'run': {
        'echo': True,
        'pty': True,
    }
})
