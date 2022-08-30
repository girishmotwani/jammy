DISPLAY_BOLD            := "\033[01m"
DISPLAY_RESET           := "\033[0;0m"
HOST_OS                 := $(shell uname)
IMAGE_NAME              ?= jammy
SUBSCRIPTION_ID         := 8897e8a2-84e5-44d7-915d-60188052a731
SUBSCRIPTION_ID2         := 7a06e974-7329-4485-87e7-3211b06c15aa
SUBSCRIPTION_ID3         := aeb5b02a-0f18-45a4-86d6-81808115cacf

setup: ## Install/reinstall all required dependencies
	pip3 install  --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt --upgrade \
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

test-fw-ipg-multiple-clients: ## Run FWM IP Groups test: Creates rules that have IP Groups in src and dst
	@echo $(DISPLAY_BOLD)"==> Running Firewall Policy IP Group tests"$(DISPLAY_RESET)
	@echo $(SUBSCRIPTION_ID)"==> id1"
	@echo $(SUBSCRIPTION_ID2)"==> id2"
	@echo $(SUBSCRIPTION_ID3)"==> id3"
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/firewall_policy/firewall_policy_test.py -k test_create_delete_vnet_fw_with_ipg_multiple_subscriptions \
	       	--resourceGroup poojaIPGLimit1 --subscriptionId $(SUBSCRIPTION_ID) --subscriptionIds $(SUBSCRIPTION_ID) $(SUBSCRIPTION_ID2) $(SUBSCRIPTION_ID3) --numrcg 1 --numrc 140  --numrules 3 \
		--location eastus2euap