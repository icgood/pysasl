# type: ignore

import nox
from glob import glob

nox.options.default_venv_backend = 'venv'
nox.options.stop_on_first_error = True

ALL_PYTHONS = (
    '3.6',
    '3.7',
    '3.8',
    '3.9',
    '3.10',
)


@nox.session(python=ALL_PYTHONS)
def tests(session):
    session.install('-U', '-r', 'requirements-dev.txt')
    session.run('py.test', '--cov=pysasl')


@nox.session(python=ALL_PYTHONS)
def type_checks(session):
    session.install('-U', '-r', 'requirements-dev.txt')
    session.run('mypy')
    session.run('pyright')
    session.run('pyright', '--verifytypes', 'pysasl')


@nox.session(python=ALL_PYTHONS)
def linters(session):
    session.install('-U', '-r', 'requirements-dev.txt')
    session.run('flake8', 'pysasl', 'test', *glob('*.py'))
    session.run('bandit', '-r', 'pysasl')
