-include .env

.PHONY: all clean deploy help install snapshot format anvil zktest

DEFAULT_ANVIL_KEY := 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

all: clean remove install update build

# Clean the repo
clean  :; forge clean

# Remove modules
remove :; rm -rf .gitmodules && rm -rf .git/modules/* && rm -rf lib && touch .gitmodules && git add . && git commit -m "modules"

install :; forge install foundry-rs/forge-std && forge install OpenZeppelin/openzeppelin-contracts && forge install Vectorized/solady && forge install JustaName-id/justanaccount --no-commit && forge install dl-solarity/solidity-lib

# Update Dependencies
update:; forge update

build:; forge build

snapshot :; forge snapshot

format :; forge fmt

anvil :; anvil -m 'test test test test test test test test test test test junk' --steps-tracing --block-time 1

deploy:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

NETWORK_ARGS := --rpc-url http://localhost:8545 --account $(LOCAL_ACCOUNT) --broadcast

ifeq ($(findstring --network mainnet,$(ARGS)),--network mainnet)
	NETWORK_ARGS := --rpc-url $(MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 1 --delay 30 --retries 3 -vvvv
endif

ifeq ($(findstring --network sepolia,$(ARGS)),--network sepolia)
	NETWORK_ARGS := --rpc-url $(SEPOLIA_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 11155111 --delay 30 --retries 3 -vvvv
endif

ifeq ($(findstring --network arb-mainnet,$(ARGS)),--network arb-mainnet)
	NETWORK_ARGS := --rpc-url $(ARB_MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 42161 -vvvv
endif

ifeq ($(findstring --network arb-sepolia,$(ARGS)),--network arb-sepolia)
	NETWORK_ARGS := --rpc-url $(ARB_SEPOLIA_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 421614 -vvvv
endif

ifeq ($(findstring --network base-mainnet,$(ARGS)),--network base-mainnet)
	NETWORK_ARGS := --rpc-url $(BASE_MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 8453 -vvvv
endif

ifeq ($(findstring --network base-sepolia,$(ARGS)),--network base-sepolia)
	NETWORK_ARGS := --rpc-url $(BASE_SEPOLIA_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 84532 -vvvv
endif

ifeq ($(findstring --network op-mainnet,$(ARGS)),--network op-mainnet)
	NETWORK_ARGS := --rpc-url $(OP_MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 10 -vvvv
endif

ifeq ($(findstring --network op-sepolia,$(ARGS)),--network op-sepolia)
	NETWORK_ARGS := --rpc-url $(OP_SEPOLIA_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 11155420 -vvvv
endif

ifeq ($(findstring --network avax-mainnet,$(ARGS)),--network avax-mainnet)
	NETWORK_ARGS := --rpc-url $(AVAX_MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.routescan.io/v2/network/mainnet/evm/43114/etherscan --etherscan-api-key $(SNOWTRACE_API_KEY) --chain 43114 -vvvv
endif

ifeq ($(findstring --network avax-fuji,$(ARGS)),--network avax-fuji)
	NETWORK_ARGS := --rpc-url $(AVAX_FUJI_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.routescan.io/v2/network/testnet/evm/43113/etherscan --etherscan-api-key $(SNOWTRACE_API_KEY) --chain 43113 -vvvv
endif

ifeq ($(findstring --network bsc-mainnet,$(ARGS)),--network bsc-mainnet)
	NETWORK_ARGS := --rpc-url $(BSC_MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 56 -vvvv
endif

ifeq ($(findstring --network bsc-testnet,$(ARGS)),--network bsc-testnet)
	NETWORK_ARGS := --rpc-url $(BSC_TESTNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 97 -vvvv
endif

ifeq ($(findstring --network linea-mainnet,$(ARGS)),--network linea-mainnet)
	NETWORK_ARGS := --rpc-url $(LINEA_MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 59144 -vvvv
endif

ifeq ($(findstring --network linea-sepolia,$(ARGS)),--network linea-sepolia)
	NETWORK_ARGS := --rpc-url $(LINEA_SEPOLIA_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --chain 59141 -vvvv
endif

ifeq ($(findstring --network celo-mainnet,$(ARGS)),--network celo-mainnet)
	NETWORK_ARGS := --rpc-url $(CELO_MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --etherscan-api-version v2 --chain 42220 -vvvv
endif

ifeq ($(findstring --network celo-sepolia,$(ARGS)),--network celo-sepolia)
	NETWORK_ARGS := --rpc-url $(CELO_SEPOLIA_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier-url https://api.etherscan.io/v2/api --etherscan-api-key $(ETHERSCAN_API_KEY) --etherscan-api-version v2 --chain 11142220 -vvvv
endif

ifeq ($(findstring --network flare-mainnet,$(ARGS)),--network flare-mainnet)
	NETWORK_ARGS := --rpc-url $(FLARE_MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier blockscout --verifier-url https://flare-explorer.flare.network/api --chain 14 -vvvv
endif

ifeq ($(findstring --network flare-coston2,$(ARGS)),--network flare-coston2)
	NETWORK_ARGS := --rpc-url $(FLARE_COSTON2_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier blockscout --verifier-url https://coston2-explorer.flare.network/api --chain 114 -vvvv
endif

ifeq ($(findstring --network ink-mainnet,$(ARGS)),--network ink-mainnet)
	NETWORK_ARGS := --rpc-url $(INK_MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier blockscout --verifier-url https://explorer.inkonchain.com/api --chain 57073 -vvvv
endif

ifeq ($(findstring --network ink-sepolia,$(ARGS)),--network ink-sepolia)
	NETWORK_ARGS := --rpc-url $(INK_SEPOLIA_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier blockscout --verifier-url https://explorer-sepolia.inkonchain.com/api --chain 763373 -vvvv
endif

ifeq ($(findstring --network dos-mainnet,$(ARGS)),--network dos-mainnet)
	NETWORK_ARGS := --rpc-url $(DOS_MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier blockscout --verifier-url https://doscan.io/api --chain 7979 -vvvv
endif

ifeq ($(findstring --network gnosis-mainnet,$(ARGS)),--network gnosis-mainnet)
	NETWORK_ARGS := --rpc-url $(GNOSIS_MAINNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier blockscout --verifier-url https://gnosis.blockscout.com/api --chain 100 -vvvv
endif

ifeq ($(findstring --network arc-testnet,$(ARGS)),--network arc-testnet)
	NETWORK_ARGS := --rpc-url $(ARC_TESTNET_RPC_URL) --account $(ACCOUNT) --broadcast --verify --verifier blockscout --verifier-url https://testnet.arcscan.app/api --chain 5042002 -vvvv
endif

deploy-mainnet:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-sepolia:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-base-mainnet:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-base-sepolia:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-op-mainnet:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-op-sepolia:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-arb-mainnet:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-arb-sepolia:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-avax-mainnet:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-avax-fuji:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-bsc-mainnet:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-bsc-testnet:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-linea-mainnet:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-linea-sepolia:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-celo-mainnet:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-celo-sepolia:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-flare-mainnet:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-flare-coston2:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-ink-mainnet:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-ink-sepolia:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-dos-mainnet:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-gnosis-mainnet:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)

deploy-arc-testnet:
	@forge script script/DeployJustaRecoveryManager.s.sol:DeployJustaRecoveryManager $(NETWORK_ARGS)