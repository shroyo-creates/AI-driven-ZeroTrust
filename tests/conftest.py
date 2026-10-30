import pytest

from pbca.simulation.data import Organization, build_trained_engine


@pytest.fixture(scope="session")
def org():
    return Organization(n_users=60, seed=11)


@pytest.fixture(scope="session")
def engine(org):
    return build_trained_engine(org)


@pytest.fixture(scope="session")
def frequent_employee(org, engine):
    return next(
        e for e in org.employees
        if e.identity.role in ("teller", "relationship_manager", "analyst")
        and engine.login_model.history(e.identity.user_id) >= 20
    )
