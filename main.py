import json
import time
import requests

from web3 import Web3
from eth_account.signers.local import LocalAccount
from eth_account import Account
from loguru import logger

from threading import Thread
from cfg import *

def check_limits(tier, amount):
    tier_limit_per_wallet = SMART_CONTRACTS['Limits'][f'tier-{tier}']
    if int(amount) > tier_limit_per_wallet:
        status = False
    else: 
        status = True
    
    return status, tier_limit_per_wallet


def check_weth_balance(prkey, tier, amount):
    main_acc: LocalAccount = Account.from_key(prkey)
    web3 = Web3(Web3.HTTPProvider(NODE_RPC))

    sale_contract_address = Web3.to_checksum_address(SMART_CONTRACTS[f'Address'])
    weth_contract_address = Web3.to_checksum_address(WETH_CONTRACT_ADDRESS)

    weth_contract = web3.eth.contract(weth_contract_address, abi=json.loads(WETH_CONTRACT_ABI))
    sale_contract = web3.eth.contract(sale_contract_address, abi=json.loads(CONTRACT_ABI))

    while True:
        try:
            check_tier_price = sale_contract.functions.tiers(SMART_CONTRACTS['Names'][f'tier-{tier}']).call()[0]
            WETH_balance_user = weth_contract.functions.balanceOf(main_acc.address).call()

            if WETH_balance_user >= check_tier_price*int(amount):
                status = True
            else:
                status = False

            return status, check_tier_price*int(amount)/1_000_000
        except Exception as e:
            logger.error(f'[{main_acc.address}] {e}')
            time.sleep(5)

def check_approve(prkey, tier, amount):
    main_acc: LocalAccount = Account.from_key(prkey)
    web3 = Web3(Web3.HTTPProvider(NODE_RPC))

    sale_contract_address = Web3.to_checksum_address(SMART_CONTRACTS[f'Address'])
    weth_contract_address = Web3.to_checksum_address(WETH_CONTRACT_ADDRESS)

    weth_contract = web3.eth.contract(weth_contract_address, abi=json.loads(WETH_CONTRACT_ABI))
    sale_contract = web3.eth.contract(sale_contract_address, abi=json.loads(CONTRACT_ABI))

    while True:
        try:
            check_tier_price = sale_contract.functions.tiers(SMART_CONTRACTS['Names'][f'tier-{tier}']).call()[0]
            check_contract_approve = weth_contract.functions.allowance(main_acc.address, sale_contract_address).call()

            if check_contract_approve >= check_tier_price * int(amount):
                return True
            else:
                return False
        except Exception as e:
            logger.error(f'[{main_acc.address}] {e}')
            time.sleep(5)

def approve(prkey, tier, amount):
    main_acc: LocalAccount = Account.from_key(prkey)
    web3 = Web3(Web3.HTTPProvider(NODE_RPC))

    sale_contract_address = Web3.to_checksum_address(SMART_CONTRACTS[f'Address'])
    weth_contract_address = Web3.to_checksum_address(WETH_CONTRACT_ADDRESS)

    weth_contract = web3.eth.contract(weth_contract_address, abi=json.loads(WETH_CONTRACT_ABI))
    sale_contract = web3.eth.contract(sale_contract_address, abi=json.loads(CONTRACT_ABI))

    while True:
        try:
            check_tier_price = sale_contract.functions.tiers(SMART_CONTRACTS['Names'][f'tier-{tier}']).call()[0]

            transaction = weth_contract.functions.approve(sale_contract_address, check_tier_price*int(amount)).build_transaction({
                'from': main_acc.address,
                'value': 0,
                'chainId': web3.eth.chain_id,
                'gasPrice': int(web3.eth.gas_price*2.1),
                'nonce': web3.eth.get_transaction_count(main_acc.address),
            })
            signed_tx = web3.eth.account.sign_transaction(transaction, main_acc._private_key)
            tx_token = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            tx_token = web3.to_hex(tx_token)
            logger.info(f'[{main_acc.address}][wETH APPROVE FOR SALE CONTRACT] Approve')

            while True:
                try:
                    receipt = web3.eth.wait_for_transaction_receipt(tx_token, timeout = 120)
                    if receipt['status'] == None:
                        logger.info(f'[{main_acc.address}][wETH APPROVE FOR SALE CONTRACT] Wait Status...')
                    elif receipt['status'] == 1:
                        logger.success(f'[{main_acc.address}][wETH APPROVE FOR SALE CONTRACT] Success')
                        return
                    elif receipt['status'] != 1:
                        logger.error(f'[{main_acc.address}][wETH APPROVE FOR SALE CONTRACT] fail. Try again...')
                except: ...
        except Exception as e:
            logger.error(f'[{main_acc.address}][wETH APPROVE FOR SALE CONTRACT] {e}')
            time.sleep(5)

def mint_node(prkey, tier, amount, data):
    main_acc: LocalAccount = Account.from_key(prkey)
    web3 = Web3(Web3.HTTPProvider(NODE_RPC))

    sale_contract_address = Web3.to_checksum_address(SMART_CONTRACTS[f'Address'])
    sale_contract = web3.eth.contract(sale_contract_address, abi=json.loads(CONTRACT_ABI))

    _amount = int(amount)
    allocatedPayment = 3100000000000000000
    zero_wallet = web3.to_checksum_address('0x0000000000000000000000000000000000000000')

    while True:
        try:
            transaction = sale_contract.functions.signedPurchaseInTierWithCode(SMART_CONTRACTS['Names'][f'tier-{tier}'], _amount, allocatedPayment, data, Web3.to_text(hexstr=SMART_CONTRACTS['Configs'][f'tier-{tier}']), zero_wallet).build_transaction({
                'from': main_acc.address,
                'value': 0,
                'chainId': web3.eth.chain_id,
                'gasPrice': int(web3.eth.gas_price*26.1),
                'nonce': web3.eth.get_transaction_count(main_acc.address),
            })
            signed_tx = web3.eth.account.sign_transaction(transaction, main_acc._private_key)
            tx_token = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            tx_token = web3.to_hex(tx_token)
            logger.info(f'[{main_acc.address}][Mint Tier {tier}] {tx_token}')

            while True:
                try:
                    receipt = web3.eth.wait_for_transaction_receipt(tx_token, timeout = 120)
                    if receipt['status'] == None:
                        logger.info(f'[{main_acc.address}][Mint Tier {tier}] Wait Status...')
                    elif receipt['status'] == 1:
                        logger.success(f'[{main_acc.address}][Mint Tier {tier}] Success')
                        with open(f'success.txt', 'a') as f:
                            f.write(f'{main_acc.address};tier-{tier};{int(amount)}\n')
                        return
                    elif receipt['status'] != 1:
                        logger.error(f'[{main_acc.address}][Mint Tier {tier}] fail. Try again...')
                except: ...

        except Exception as e:
            logger.error(f'[{main_acc.address}][Mint Tier {tier}] {e}')

def get_data(prkey, tier):
    main_acc: LocalAccount = Account.from_key(prkey)

    while True:
        try:
            url = f'https://backend.impossible.finance/api/backend-service/allocation/icn?address={main_acc.address}&tierId={SMART_CONTRACTS['Names'][f'tier-{tier}']}'

            json_data = {
                'address':f'{main_acc.address}',
                'saleAddress':f'{SMART_CONTRACTS[f"Address"]}',
                'tierId':f'{SMART_CONTRACTS['Names'][f'tier-{tier}']}',
            }
            json_data = json.dumps(json_data)

            resp = requests.post(url=url, data=json_data)
            if resp.status_code == 200:
                a = json.loads(resp.text)
                data = a['data']
                return data
            else: time.sleep(0.5)
        except Exception as e:
            logger.error(f'[{main_acc.address}][get data] {e}')
            time.sleep(0.5)

def start(prkey, tier, amount):
    main_acc: LocalAccount = Account.from_key(prkey)
    logger.info(f'[{main_acc.address}] Start')

    limit_status, tier_limit_per_wallet = check_limits(tier, amount)
    if limit_status == False: 
        logger.error(f'[{main_acc.address}] You can buy no more than {tier_limit_per_wallet} nodes of the {tier} tier | Нельзя купить более {tier_limit_per_wallet} нод {tier}го тира')
        return

    check_balance_status, needed_tokens = check_weth_balance(prkey, tier, amount)

    if check_balance_status == False:
        logger.error(f'[{main_acc.address}] Insufficient balance wETH. Minimum of {(needed_tokens)} wETH is required | Недостаточный баланс wETH. Необходимо минимум {needed_tokens} wETH')
        return

    approve_status = check_approve(prkey, tier, amount)
    if approve_status == False:
        approve(prkey, tier, amount)

    logger.info(f'[{main_acc.address}] Wait 60 seconds before starting to retrieve transaction data | Ожидаем 60 секунд до старта, чтобы получить данные транзакции')
    while True:
        if time.time() > 1731499200 - 60:
            break
        else: time.sleep(0.5)

    #ПОЛУЧАЕМ СИГНАТУРУ
    data = get_data(prkey, tier)

    logger.info(f'[{main_acc.address}] Waiting 5 seconds for the sale to start | Ожидаем 5 секунд до старта')
    while True:
        if time.time() > 1731499200 - 5:
            break
        else: time.sleep(0.5)

    i = 0
    while i < 5: # Increase if you want to run with a large number of threads | Увеличьте, если хотите запустить с бОльшим кол-вом потоков
        Thread(target=mint_node, args=(prkey, tier, amount, data)).start()
        i = i+1

file_name = 'wallets'
accs_list = open(file_name + '.txt', 'r').read().splitlines()

for el in accs_list:
    splited_data = el.split(';')
    prkey = splited_data[0]
    tier = splited_data[1]
    amount = splited_data[2]

    Thread(target=start, args=(prkey, tier, amount)).start()
    time.sleep(0.01)