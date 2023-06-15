DISPLAY_BOLD            := "\033[01m"
DISPLAY_RESET           := "\033[0;0m"
IMAGE_NAME              ?= jammy
SUBSCRIPTION_ID         := $(AZURE_SUBSCRIPTION_ID)
SUBSCRIPTION_ID2         := $(AZURE_SUBSCRIPTION_ID1)
SUBSCRIPTION_ID3         := $(AZURE_SUBSCRIPTION_ID2)

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
	       	--resourceGroup test01RG D8-BB-C1-29-4C-8B--subscriptionId $(SUBSCRIPTION_ID) \
		--location westus

test-vwan: ## Run vWan tests
	@echo $(DISPLAY_BOLD)"==> Running virtual WAN tests"$(DISPLAY_RESET)
	python -m pytest --html=jammy_vwantest_report.html --self-contained-html --capture=sys -rF tests/virtualWan/virtual_wan_test.py \
	       	--resourceGroup testWan01RG --subscriptionId $(SUBSCRIPTION_ID) \
		--location westus

test-fw-ipg: ## Run FWM IP Groups test: Creates rules that have IP Groups in src and dst
	@echo $(DISPLAY_BOLD)"==> Running Firewall Policy IP Group tests"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/firewall_policy/firewall_policy_test.py -k test_create_delete_vnet_fw_with_ipg \
	       	--resourceGroup jammy_putest --subscriptionId $(SUBSCRIPTION_ID)  --numrcg 1 --numrc 1 --numrules 5 \
		--location eastus

test-vent-fwp-ipg-setup: ## Run FWM IP Groups test: Creates rules that have IP Groups in src and dst
	@echo $(DISPLAY_BOLD)"==> Running Firewall Policy IP Group tests"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/ip_group/ip_group_tests.py -k test_create_vnet_fw_with_ipg \
	       	--resourceGroup JAMMYTEST_IPG_1 --subscriptionId 66de82f3-ad93-4605-bbdb-237fe7ef3a06  --numrcg 1 --numrc 1 --numrules 1 \
		--location eastus

######################
### IP Group Tests ###
######################
test-fwp-ipg-setup: ## Creates setup to run  FWM IP Groups test: Creates rules that have IP Groups in src and dst
	@echo $(DISPLAY_BOLD)"==> Running IP Groups setup Creation"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/ip_group/ip_group_tests.py -k test_create_vnet_fw_with_ipg \
	       	--resourceGroup BUG_BASH_IPG_northcentralus_setup --subscriptionId f6cb8187-b300-4c2d-9b23-c00e7e98d799  --numrcg 5 --numrc 1 --numrules 5 \
		--location northcentralus

test-fwp-ipg-update-parallel: ## Run FWM IP Groups test: tests updating IP groups in parallel. Run after 'test-fwp-ipg-setup'
	@echo $(DISPLAY_BOLD)"==> Running IP Groups Parallel Update"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/ip_group/ip_group_tests.py -k test_ipg_update_parallel \
	       	--resourceGroup JAMMYTEST_IPG_eastus2euap_3 --subscriptionId 8897e8a2-84e5-44d7-915d-60188052a731  --numrcg 5 --numrc 1 --numrules 5 \
		--location eastus2euap

test-fwp-ipg-setup-delete: ## Creates setup to run  FWM IP Groups test
	@echo $(DISPLAY_BOLD)"==> Running Firewall Policy IP Group tests"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/ip_group/ip_group_tests.py -k test_delete_vnet_fw_with_ipg \
	       	--resourceGroup JAMMYTEST_IPG_eastus2euap_1 --subscriptionId 66de82f3-ad93-4605-bbdb-237fe7ef3a06  \
		--location eastus2euap

test-fwp-ipg-update-continuous: ## Run FWM IP Groups test: tests updating IP groups. Run after 'test-fwp-ipg-setup'
	@echo $(DISPLAY_BOLD)"==> Running IP Groups Parallel Update"$(DISPLAY_RESET)
	python -m pytest --html=jammy_test-fwp-ipg-update-continuous_30_report.html --self-contained-html --capture=tee-sys -rF tests/ip_group/ip_group_tests.py -k test_ipg_update_continuous \
	       	--resourceGroup BUG_BASH_IPG_westcentralus --subscriptionId f6cb8187-b300-4c2d-9b23-c00e7e98d799  --numrcg 5 --numrc 1 --numrules 5 \
		--location westcentralus

test-fwp-ipg-update-crossregion: ## Run FWM IP Groups test: tests updating IP groups. Run after 'test-fwp-ipg-setup'
	@echo $(DISPLAY_BOLD)"==> Running IP Groups cross region"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/ip_group/ip_group_tests.py -k test_ipg_update_crossregion \
	       	--resourceGroup BUG_BASH_IPG_westcentralus --subscriptionId f6cb8187-b300-4c2d-9b23-c00e7e98d799  --numrcg 5 --numrc 1 --numrules 5 \
		--location westcentralus

test_create_update_delete_large_rcg:
	@echo $(DISPLAY_BOLD)"==> Running Firewall Policy IP Group tests"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/firewall_policy/firewall_policy_test.py -k test_create_update_delete_large_rcg\
	       	--resourceGroup JAMMYtestLargeRcg --subscriptionId $(SUBSCRIPTION_ID)   \
		--location eastus2euap

test-fw-ipg-multiple-clients: ## Run FWM IP Groups test: Creates rules that have IP Groups in src and dst
	@echo $(DISPLAY_BOLD)"==> Running Firewall Policy IP Group tests"$(DISPLAY_RESET)
	@echo $(SUBSCRIPTION_ID)"==> id1"
	@echo $(SUBSCRIPTION_ID2)"==> id2"
	@echo $(SUBSCRIPTION_ID3)"==> id3"
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/firewall_policy/firewall_policy_test.py -k test_create_delete_vnet_fw_with_ipg_multiple_subscriptions \
	       	--resourceGroup poojaIPGLimit3 --subscriptionId $(SUBSCRIPTION_ID) --subscriptionIds $(SUBSCRIPTION_ID) $(SUBSCRIPTION_ID2) $(SUBSCRIPTION_ID3) --numrcg 1 --numrc 1  --numrules 3 \
		--location eastus2euap



test_create_endurance_setup:
	@echo $(DISPLAY_BOLD)"==> Creating Basic Endurance Setup A"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/firewall_policy/azure_firewall_iperf_test.py -k test_basic_sku_iperf \
	       	--resourceGroup AzureFirewallBasicSkuEnduranceTestRG_A --subscriptionId f6cb8187-b300-4c2d-9b23-c00e7e98d799   \
		--location eastus2  --policyLocation eastus2
	@echo $(DISPLAY_BOLD)"==> Creating Basic Endurance Setup B"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/firewall_policy/azure_firewall_iperf_test.py -k test_basic_sku_iperf \
	       	--resourceGroup AzureFirewallBasicSkuEnduranceTestRG_B --subscriptionId f6cb8187-b300-4c2d-9b23-c00e7e98d799   \
		--location eastus2  --policyLocation eastus2
	@echo $(DISPLAY_BOLD)"==> Creating Standard Endurance Setup A"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/firewall_policy/azure_firewall_iperf_test.py -k test_standard_sku_iperf \
	       	--resourceGroup AzureFirewallStandardSkuEnduranceTestRG_A --subscriptionId f6cb8187-b300-4c2d-9b23-c00e7e98d799   \
		--location eastus2  --policyLocation eastus2
	@echo $(DISPLAY_BOLD)"==> Creating Standard Endurance Setup B"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/firewall_policy/azure_firewall_iperf_test.py -k test_standard_sku_iperf \
	       	--resourceGroup AzureFirewallStandardSkuEnduranceTestRG_B --subscriptionId f6cb8187-b300-4c2d-9b23-c00e7e98d799   \
		--location eastus2  --policyLocation eastus2
	@echo $(DISPLAY_BOLD)"==> Creating Premium Endurance Setup A"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/firewall_policy/azure_firewall_iperf_test.py -k test_premium_sku_iperf \
	       	--resourceGroup AzureFirewallPremiumSkuEnduranceTestRG_A --subscriptionId f6cb8187-b300-4c2d-9b23-c00e7e98d799   \
		--location eastus2  --policyLocation eastus2
	@echo $(DISPLAY_BOLD)"==> Creating Premium Endurance Setup B"$(DISPLAY_RESET)
	python -m pytest --html=jammy_fwmtest_report.html --self-contained-html --capture=sys -rF tests/firewall_policy/azure_firewall_iperf_test.py -k test_premium_sku_iperf \
	       	--resourceGroup AzureFirewallPremiumSkuEnduranceTestRG_B --subscriptionId f6cb8187-b300-4c2d-9b23-c00e7e98d799   \
		--location eastus2  --policyLocation eastus2
