DISPLAY_BOLD            := "\033[01m"
DISPLAY_RESET           := "\033[0;0m"
HOST_OS                 := $(shell uname)
IMAGE_NAME              ?= jammy
SUBSCRIPTION_ID         := $(AZURE_SUBSCRIPTION_ID)

setup: ## Install/reinstall all required dependencies
	pip3 install  --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt --upgrade ;\
	cd lib && pip3 install --user -e .

setup-windows: ## Install/reinstall all required dependencies
	pip3 install  --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt --upgrade \
	&& cd lib && pip3 install -e .

install: ## Install python modules
	cd lib && pip3 install --user -e .

auth-and-test: ## Run FWM feature tests in one job
	armclient.exe login
	@echo $(DISPLAY_BOLD)"==> Running Firewall Policy tests"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/firewall_policy/firewall_policy_test.py \
	       	--resourceGroup test01RG --subscriptionId $(SUBSCRIPTION_ID) \
		--location westus
test: ## Run FWM feature tests in one job
	@echo $(DISPLAY_BOLD)"==> Running Firewall Policy tests"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/firewall_policy/firewall_policy_test.py \
	       	--resourceGroup test01RG --subscriptionId $(SUBSCRIPTION_ID) \
		--location westus

test-vwan: ## Run vWan tests
	@echo $(DISPLAY_BOLD)"==> Running virtual WAN tests"$(DISPLAY_RESET)
	python -m pytest --html=jammy_vwantest_report.html --self-contained-html --capture=sys -rF tests/virtualWan/virtual_wan_test.py \
	       	--resourceGroup testWan01RG --subscriptionId $(SUBSCRIPTION_ID) \
		--location westus

test-fw-ipg: ## Run FWM IP Groups test: Creates rules that have IP Groups in src and dst
	@echo $(DISPLAY_BOLD)"==> Running Firewall Policy IP Group tests"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/firewall_policy/firewall_policy_test.py -k test_create_delete_vnet_fw_with_ipg \
	       	--resourceGroup testfwIPG --subscriptionId $(SUBSCRIPTION_ID)  --numrcg 5 --numrc 2  --numrules 2 \
		--location eastus2euap