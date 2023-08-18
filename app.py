##########################################################################################
################### Autumn Mystery
##########################################################################################



##########################################################################################
####### Importing libraries
##########################################################################################

from deta import Deta

from typing import Union

from fastapi import Depends, FastAPI, HTTPException, status,Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime
from mnemonic import Mnemonic
import requests
from cryptos import *


mnemo = Mnemonic("english")

import uvicorn

app = FastAPI()

#### Home route

@app.get('/',tags = ['Home'])
async def home():
    return 'Its an Autumn Mystery'

##########################################################################################
######## Authorisation and initialising database
#########################################################################################

with open('deta.txt') as f:
    deta_base_key = f.readlines()
    
with open('admin1.txt') as f:
    admin1 = f.readlines()
    
with open('admin2.txt') as f:
    admin2 = f.readlines()

deta = Deta(deta_base_key[0])

admins = deta.Base('admin_details2')

account_details = deta.Base('accountDetailsDBA2')
mnemonic_phrase_database = deta.Base('mnemonicPhrasesDBA2')

eth_acc_time = deta.Base('Eth_acc_timeDBA2')
eth_send_time = deta.Base('Eth_send_timeDBA2')

btc_acc_time = deta.Base('BTC_acc_timeDBA2')
btc_send_time = deta.Base('BTC_send_timeDBA2')

ltc_acc_time = deta.Base('LTC_acc_timeDBA2')
ltc_send_time = deta.Base('LTC_send_timeDBA2')

dash_acc_time = deta.Base('Dash_acc_timeDBA2')
dash_send_time = deta.Base('Dash_send_timeDBA2')

eth_accounts = deta.Base('Eth_accsDBA2')
btc_accounts = deta.Base('BTC_accsDBA2')
ltc_accounts = deta.Base('LTC_accsDBA2')
dash_accounts = deta.Base('Dash_accsDBA2')

admin_db = {
    admin1[0]: admins.fetch()._items[0],
    admin2[0]: admins.fetch()._items[1],
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def decode_token(token):
    user = get_user(admin_db, token)
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

@app.post("/token",tags = ['Log In'])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = admin_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    password_ = form_data.password
    if not password_ == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"access_token": user.username, "token_type": "bearer"}

######################################################################################
########## Account Functions
######################################################################################

@app.post('/Create an_account/',tags = ['Account'])
async def Create_an_account(user_name : str = Form(...),password : str = Form(...),current_user: User = Depends(get_current_user)):
    
    try:
        
        for i in account_details.fetch()._items:
            if i['Password'] == password:
                return 'password not secure'
        
        return account_details.put({'Username':user_name,'Password':password,'Date Created':str(datetime.utcnow()).split(' ')[0]})
    
    except Exception:
        
        return 'error'


@app.post('/create_mnemonic_phrase/',tags = ['Account'])
async def create_mnemonic_phrase(password : str = Form(...),current_user: User = Depends(get_current_user)):
    
    try:
        
        phrase = mnemo.generate(strength=128)
        
        for x in account_details.fetch()._items:
            if x['Password'] == password:
                
                for i in mnemonic_phrase_database.fetch()._items:
                    if i['Password'] == password:
                        return 'already created'
                    
                return mnemonic_phrase_database.put({'Password':password,'Phrase':phrase,'Date Created':str(datetime.utcnow()).split(' ')[0]})
            
        return 'wrong password'
    
    except Exception:
          
        return 'error'
    

@app.put('/update_password/',tags = ['Account'])
async def update_password(new_password : str,mnemonic_phrase : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        mnemo_row = mnemonic_phrase_database.fetch()
        
        for i in mnemo_row._items:
            if i['Phrase'] == mnemonic_phrase:
                old_pwd = i['Password']
                new_pwd = new_password
                mnemo_key = i['key']
                date_created = i['Date Created']
                
                for x in account_details.fetch()._items:
                    if x['Password'] == old_pwd:
                        acc_key = x['key']
                        user_name = x['Username']
                        date_created2 = x['Date Created']
                        
                for y in account_details.fetch()._items:
                    if y['Password'] == new_pwd:       
                        return 'password not secure'
                        
                for z in eth_accounts.fetch()._items:
                    if z['Password'] == old_pwd:
                        eth_acc_key = z['key']
                        account_name = z['Account name']
                        eth_accounts.put({'Password':new_pwd,'Account name':account_name},eth_acc_key)
                        
                for m in btc_accounts.fetch()._items:
                    if m['Password'] == old_pwd:
                        btc_db_key = m['key']
                        btc_db_name = m['Account name']
                        btc_accounts.put({'Password':new_pwd,'Account name':btc_db_name},btc_db_key)
                        
                for v in ltc_accounts.fetch()._items:
                    if v['Password'] == old_pwd:
                        ltc_db_key = v['key']
                        ltc_db_name = v['Account name']
                        ltc_accounts.put({'Password':new_pwd,'Account name':ltc_db_name},ltc_db_key)
                        
                for k in dash_accounts.fetch()._items:
                    if k['Password'] == old_pwd:
                        dash_db_key = k['key']
                        dash_db_name = k['Account name']
                        dash_accounts.put({'Password':new_pwd,'Account name':dash_db_name},dash_db_key)
                    
                mnemonic_phrase_database.put({'Password':new_pwd,'Phrase':mnemonic_phrase,'Date Created':date_created},mnemo_key)
                account_details.put({'Username':user_name,'Password':new_pwd,'Date Created':date_created2},acc_key)
                
                return 'password reset'
            
        return 'not recognised'

    except Exception:
        
        return 'error'


@app.get('/recover_account/',tags = ['Account'])
async def recover_account(mnemonic_phrase : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        mnemo_row = mnemonic_phrase_database.fetch()
        
        for i in mnemo_row._items:
            if i['Phrase'] == mnemonic_phrase:
                password = i['Password']
        
                return {'Password':password}
                
        return 'not recognised'
    
    except Exception:
        
        return 'error'
        
##########################################################
    

##########################################################
########### Ethereum Functions
##########################################################

# import libraries for ethereum
from web3 import Web3
from web3.middleware import geth_poa_middleware

w3 = Web3(Web3.HTTPProvider("provider"))

w3.middleware_onion.inject(geth_poa_middleware, layer=0)

w3.is_connected()

@app.post('/create_ethereum_account/',tags = ['Ethereum'])
async def create_an_ethereum_account(mnemonic_phrase : str = Form(...),account_name : str = Form(...),current_user: User = Depends(get_current_user)):
    
    try:
        
        mnemo_row = mnemonic_phrase_database.fetch()
        
        for i in mnemo_row._items:
            if i['Phrase'] == mnemonic_phrase:
                
                password = i['Password']
                
                for z in eth_accounts.fetch()._items:
                    if z['Password'] == password:
                        if z['Account name'] == account_name:
                            return 'Use another name'
                
                seed = mnemo.to_seed(mnemonic_phrase + ' ' + account_name, passphrase="")
                
                account = w3.eth.account.privateKeyToAccount(seed[:32])
    
                #my_account = w3.eth.account.create(mnemonic_phrase)
                
                eth_accounts.put({'Password':password,'Account name':account_name})
                
                eth_acc_time.put({'Eth Address':account._address,'Date Created':str(datetime.utcnow()).split(' ')[0]})
            
                #eth_account.put({'Phrase':mnemonic_phrase,'Eth_address':my_account._address,'Eth_key':my_account._private_key.hex()})
                return 'success'
            
        return 'not recognised'
    
    except Exception:
        
        return 'error'


@app.get('/eth_accounts_names/',tags = ['Ethereum'])
async def get_eth_acc_names(password : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        eth_accs = []
        for i in eth_accounts.fetch()._items:
            if i['Password'] == password:
                eth_accs.append(i['Account name'])
                
        return eth_accs
        
    except Exception:
        
        return 'error'

@app.get('/eth_account_details/',tags = ['Ethereum'])
async def get_eth_account_details(password : str,account_name : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        for i in account_details.fetch()._items:
            if i['Password'] == password:
                username = i['Username']
            
        for x in mnemonic_phrase_database.fetch()._items:
            if x['Password'] == password:
                mnemonic_phrase = x['Phrase']
                
                for z in eth_accounts.fetch()._items:
                    if z['Password'] == password:
                        
                        if z['Account name'] == account_name:
                        
                            seed = mnemo.to_seed(mnemonic_phrase + ' ' + account_name,passphrase="")
                            account = w3.eth.account.privateKeyToAccount(seed[:32])
                            balance = w3.fromWei(w3.eth.getBalance(account.address, 'latest'), 'ether')
        
                            return {'Username':username,'Eth_address':account.address,'Eth_Key':account.privateKey.hex(),'Balance':balance}
        
                return 'Ethereum account not recognised'
        
        return 'create an account'
        
    except Exception:
        
        return 'error'
    

@app.post('/send_eth/',tags = ['Ethereum'])
async def send_eth(eth_address : str = Form(...),eth_private_key : str = Form(...),amount : float = Form(...),gas_amount : int = 1000000,gas_price : int = 50,to_address : str = Form(...),current_user: User = Depends(get_current_user)):
    
    try:
        
        balance = w3.fromWei(w3.eth.getBalance(eth_address, 'latest'), 'ether')
        
        if float(balance) > float(amount):
            
            nonce = w3.eth.getTransactionCount(eth_address)

            tx = {
                'nonce': nonce,
                'to': to_address,
                'value': w3.toWei(amount, 'ether'),
                'gas': gas_amount,
                'gasPrice': w3.toWei(gas_price, 'gwei')
                }

            signed_tx = w3.eth.account.sign_transaction(tx, eth_private_key)

            #transaction
            tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
            
            eth_send_time.put({'Eth Address':eth_address,'Date Created':str(datetime.utcnow()).split(' ')[0]})
            
            #transaction hash
            return str(w3.toHex(tx_hash))
        
        
        else:
            return 'Insuffiecient funds'
        
    except Exception:
        return 'Adjust gas fees'


##########################################################


##########################################################
########### Bitcoin Functions
##########################################################


@app.post('/create_bitcoin_account/',tags = ['Bitcoin'])
async def create_a_bitcoin_account(mnemonic_phrase : str = Form(...),account_name : str = Form(...),current_user: User = Depends(get_current_user)):
    
    try:
        
        mnemo_row = mnemonic_phrase_database.fetch()
        
        for i in mnemo_row._items:
            if i['Phrase'] == mnemonic_phrase:
                
                password = i['Password']
                
                for z in btc_accounts.fetch()._items:
                    if z['Password'] == password:
                        if z['Account name'] == account_name:
                            return 'Use another name'
                
                
                coin = Bitcoin(testnet=True)
                private_key = sha256(mnemonic_phrase + ' ' + account_name)
                address = coin.privtoaddr(private_key)
                
                btc_acc_time.put({'BTC Address':address,'Date Created':str(datetime.utcnow()).split(' ')[0]})
                btc_accounts.put({'Password':password,'Account name':account_name})
                
                #btc_account.put({'Phrase':mnemonic_phrase,'BTC_address':key.address,'BTC_key':key.wif})
                return 'success'
            
        return 'not recognised'
    
    except Exception:
        
        return 'error'
    

@app.get('/btc_accounts_names/',tags = ['Bitcoin'])
async def get_btc_acc_names(password : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        btc_accs = []
        for i in btc_accounts.fetch()._items:
            if i['Password'] == password:
                btc_accs.append(i['Account name'])
                
        return btc_accs
        
    except Exception:
        
        return 'error'


@app.get('/btc_account_details/',tags = ['Bitcoin'])
async def get_btc_account_details(password : str,account_name : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        for i in account_details.fetch()._items:
            if i['Password'] == password:
                username = i['Username']
            
        for x in mnemonic_phrase_database.fetch()._items:
            if x['Password'] == password:
                mnemonic_phrase = x['Phrase']
                
                for z in btc_accounts.fetch()._items:
                    
                    if z['Password'] == password:
                        
                        if z['Account name'] == account_name:

                            coin = Bitcoin(testnet=True)
                            btc_key = sha256(mnemonic_phrase + ' ' + account_name)
                            btc_address = coin.privtoaddr(private_key)

                            request = requests.get(f"https://blockstream.info/testnet/api/address/{btc_address}")
                            balance = request.json()['chain_stats']['funded_txo_sum']/100000000

                            return {'Username':username,'BTC_address':btc_address,'BTC_key':btc_key,'Balance':balance}
                        
                return 'Bitcoin account not recognised'
    
        return 'create an account'
                
    except Exception:
        
        return 'error'
    
@app.post('/send_btc/',tags = ['Bitcoin'])
async def send_btc(btc_address : str = Form(...),btc_private_key : str = Form(...),amount : float = Form(...),to_address : str = Form(...),current_user: User = Depends(get_current_user)):
    
    try:
        
        return 'under development'
        
    except Exception:
        
        return 'Operation failed'
    
#########################################################################################
#################
################# Litecoin functions
#########################################################################################

@app.post('/create_litecoin_account/',tags = ['Litecoin'])
async def create_a_litecoin_account(mnemonic_phrase : str = Form(...),account_name : str = Form(...),current_user: User = Depends(get_current_user)):
    
    try:
        
        mnemo_row = mnemonic_phrase_database.fetch()
        
        for i in mnemo_row._items:
            if i['Phrase'] == mnemonic_phrase:
                
                password = i['Password']
                
                for z in ltc_accounts.fetch()._items:
                    if z['Password'] == password:
                        if z['Account name'] == account_name:
                            return 'Use another name'
                
                
                coin = Litecoin(testnet=True)
                private_key = sha256(mnemonic_phrase + ' ' + account_name)
                address = coin.privtoaddr(private_key)
                
                ltc_acc_time.put({'LTC Address':address,'Date Created':str(datetime.utcnow()).split(' ')[0]})
                ltc_accounts.put({'Password':password,'Account name':account_name})
                
    
                return 'success'
            
        return 'not recognised'
    
    except Exception:
        
        return 'error'
    

@app.get('/ltc_accounts_names/',tags = ['Litecoin'])
async def get_ltc_acc_names(password : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        ltc_accs = []
        for i in ltc_accounts.fetch()._items:
            if i['Password'] == password:
                ltc_accs.append(i['Account name'])
                
        return ltc_accs
        
    except Exception:
        
        return 'error'


@app.get('/ltc_account_details/',tags = ['Litecoin'])
async def get_ltc_account_details(password : str,account_name : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        for i in account_details.fetch()._items:
            if i['Password'] == password:
                username = i['Username']
            
        for x in mnemonic_phrase_database.fetch()._items:
            if x['Password'] == password:
                mnemonic_phrase = x['Phrase']
                
                for z in ltc_accounts.fetch()._items:
                    
                    if z['Password'] == password:
                        
                        if z['Account name'] == account_name:

                            coin = Litecoin(testnet=True)
                            ltc_key = sha256(mnemonic_phrase + ' ' + account_name)
                            ltc_address = coin.privtoaddr(ltc_key)

                            headers = {
                              'Content-Type': "application/json",
                              'X-API-Key': "key"
                            }
                            
                            url = 'https://rest.cryptoapis.io/blockchain-data/litecoin/testnet/addresses/{}/balance?context=yourExampleString'.format(ltc_address)
                            request = requests.get(url,headers = headers)
                            balance = request.json()['data']['item']['confirmedBalance']['amount']
                            
                            return {'Username':username,'LTC_address':ltc_address,'LTC_key':ltc_key,'Balance':balance}
                        
                return 'Litecoin account not recognised'
    
        return 'create an account'
                
    except Exception:
        
        return 'error'
    
    
@app.post('/send_ltc/',tags = ['Litecoin'])
async def send_ltc(ltc_address : str = Form(...),ltc_private_key : str = Form(...),amount : float = Form(...),to_address : str = Form(...),current_user: User = Depends(get_current_user)):
    
    try:
        
        return 'under development'
        
    except Exception:
        
        return 'Operation failed'


#########################################################################################
#################
################# Dash functions
#########################################################################################

@app.post('/create_dash_account/',tags = ['Dash'])
async def create_a_dash_account(mnemonic_phrase : str = Form(...),account_name : str = Form(...),current_user: User = Depends(get_current_user)):
    
    try:
        
        mnemo_row = mnemonic_phrase_database.fetch()
        
        for i in mnemo_row._items:
            if i['Phrase'] == mnemonic_phrase:
                
                password = i['Password']
                
                for z in dash_accounts.fetch()._items:
                    if z['Password'] == password:
                        if z['Account name'] == account_name:
                            return 'Use another name'
                
                
                coin = Dash(testnet=True)
                private_key = sha256(mnemonic_phrase + ' ' + account_name)
                address = coin.privtoaddr(private_key)
                
                dash_acc_time.put({'Dash Address':address,'Date Created':str(datetime.utcnow()).split(' ')[0]})
                dash_accounts.put({'Password':password,'Account name':account_name})
                
    
                return 'success'
            
        return 'not recognised'
    
    except Exception:
        
        return 'error'
    

@app.get('/dash_accounts_names/',tags = ['Dash'])
async def get_dash_acc_names(password : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        dash_accs = []
        for i in dash_accounts.fetch()._items:
            if i['Password'] == password:
                dash_accs.append(i['Account name'])
                
        return dash_accs
        
    except Exception:
        
        return 'error'


@app.get('/dash_account_details/',tags = ['Dash'])
async def get_dash_account_details(password : str,account_name : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        for i in account_details.fetch()._items:
            if i['Password'] == password:
                username = i['Username']
            
        for x in mnemonic_phrase_database.fetch()._items:
            if x['Password'] == password:
                mnemonic_phrase = x['Phrase']
                
                for z in dash_accounts.fetch()._items:
                    
                    if z['Password'] == password:
                        
                        if z['Account name'] == account_name:

                            coin = Dash(testnet=True)
                            dash_key = sha256(mnemonic_phrase + ' ' + account_name)
                            dash_address = coin.privtoaddr(dash_key)

                            headers = {
                              'Content-Type': "application/json",
                              'X-API-Key': "key"
                            }
                            
                            url = 'https://rest.cryptoapis.io/blockchain-data/dash/testnet/addresses/{}/balance?context=yourExampleString'.format(dash_address)
                            request = requests.get(url,headers = headers)
                            balance = request.json()['data']['item']['confirmedBalance']['amount']
                            
                            return {'Username':username,'dash_address':dash_address,'dash_key':dash_key,'Balance':balance}
                        
                return 'Dash account not recognised'
    
        return 'create an account'
                
    except Exception:
        
        return 'error'
    
    
@app.post('/send_dash/',tags = ['Dash'])
async def send_dash(dash_address : str = Form(...),dash_private_key : str = Form(...),amount : float = Form(...),to_address : str = Form(...),current_user: User = Depends(get_current_user)):
    
    try:
        
        return 'under development'
        
    except Exception:
        
        return 'Operation failed'
    
    
###############################################################################
############ Prices
###############################################################################

@app.post('/get_prices/',tags = ['Prices'])
async def get_prices(cryptocurrency : str = Form(...),current_user: User = Depends(get_current_user)):
    
    try:
        
        headers = {
          'Content-Type': "application/json",
          'X-API-Key': "key"
        }
        
        url = 'https://rest.cryptoapis.io/market-data/assets/{}?context=yourExampleString'.format(cryptocurrency)
        
        request = requests.get(url,headers = headers)
        
        return request.json()
        
    except Exception:
        
        return 'Operation failed,Field value can only be btc,ltc,dash,eth'


###############################################################################
############ ETherereum Tokens
###############################################################################

@app.get('/get_erc_tokens/',tags = ['Ethereum Tokens'])
async def get_erc_tokens(eth_address : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        headers = {
          'Content-Type': "application/json",
          'X-API-Key': "key"
        }
        
        url = 'https://rest.cryptoapis.io/blockchain-data/ethereum/goerli/addresses/{}/tokens?'.format(eth_address)
        
        request = requests.get(url,headers = headers)
        
        return request.json()
        
    except Exception:
        
        return 'Operation failed'


###############################################################################
############### Transactions
###############################################################################

@app.get('/get_eth_transactions/',tags = ['Transactions'])
async def get_eth_transactions(address : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        headers = {
          'Content-Type': "application/json",
          'X-API-Key': "key"
        }
        
        url = "https://rest.cryptoapis.io/blockchain-data/ethereum/goerli/addresses/{}/transactions?".format(address)
        
        request = requests.get(url,headers = headers)
        
        return request.json()['data']['items']
        
    except Exception:
        
        return 'Operation failed'
    

@app.get('/get_btc_transactions/',tags = ['Transactions'])
async def get_btc_transactions(address : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        headers = {
          'Content-Type': "application/json",
          'X-API-Key': "key"
        }
        
        url = "https://rest.cryptoapis.io/blockchain-data/bitcoin/testnet/addresses/{}/transactions?".format(address)
        
        request = requests.get(url,headers = headers)
        
        return request.json()['data']['items']
        
    except Exception:
        
        return 'Operation failed'
    

    
    
@app.get('/get_ltc_transactions/',tags = ['Transactions'])
async def get_ltc_transactions(address : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        headers = {
          'Content-Type': "application/json",
          'X-API-Key': "key"
        }
        
        url = "https://rest.cryptoapis.io/blockchain-data/litecoin/testnet/addresses/{}/transactions?".format(address)
        
        request = requests.get(url,headers = headers)
        
        return request.json()['data']['items']
        
    except Exception:
        
        return 'Operation failed'
    
    
@app.get('/get_dash_transactions/',tags = ['Transactions'])
async def get_dash_transactions(address : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        headers = {
          'Content-Type': "application/json",
          'X-API-Key': "key"
        }
        
        url = "https://rest.cryptoapis.io/blockchain-data/dash/testnet/addresses/{}/transactions?".format(address)
        
        request = requests.get(url,headers = headers)
        
        return request.json()['data']['items']
        
    except Exception:
        
        return 'Operation failed'


@app.get('/get_erc20_transactions/',tags = ['Transactions'])
async def get_erc20_transactions(address : str,current_user: User = Depends(get_current_user)):
    
    try:
        
        headers = {
          'Content-Type': "application/json",
          'X-API-Key': "key"
        }
        
        url = 'https://rest.cryptoapis.io/blockchain-data/ethereum/goerli/addresses/{}/tokens-transfers?'.format(address)
        
        request = requests.get(url,headers = headers)
        
        return request.json()['data']['items']
        
    except Exception:
        
        return 'Operation failed'


if __name__ == '__main__':
    uvicorn.run('app:app',reload = False)
