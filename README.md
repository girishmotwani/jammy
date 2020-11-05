# Jammy
A testing tool for Azure resources, based on PyTest.

Write end-to-end tests for Azure resources.

## reference

Refer to the [pytest documentation](https://pytest.org) for information on the test framework.

## requirements
* git
* Python 3.8.2 (tested with wsl2 on Windows 10)
* Armclient [armclient](https://github.com/projectkudu/ARMClient)

## setup and configuration
**Clone the repository**:
```
$ git clone
```

**Set the environment variable AZURE_SUBSCRIPTION_ID to the Azure Subscription
```
$ export AZURE_SUBSCRIPTION_ID=<subscriptionId>
```
**Install modules and pip-install any required dependencies**:
```
$ make setup
```

## running tests
You must invoke py.test from the root directory to properly collect conftest fixtures.

Consider the following basic run:
```
$ make auth-and-test
```
This will first prompt for user credentials to allow the framework to submit resource CRUD requests for the subscription

## writing tests

**Style Guide**:
The Google Python Style Guide has the following convention:

module_name, package_name, ClassName, method_name, ExceptionName, function_name, GLOBAL_CONSTANT_NAME, global_var_name, instance_var_name, function_parameter_name, local_var_name.

**Tests**:

A general rule of thumb is that all tests (their function names, to be exact) need to be prefixed with 'test_'. This is how pytest will recognize a function as a test.
