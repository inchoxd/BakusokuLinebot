# fastapi関係
from fastapi import FastAPI, HTTPException, Request, Header

# jwt生成関係
import os
import jwt
from jwt.algorithms import RSAAlgorithm
import time
from dotenv import load_dotenv

# アクセストークンの生成やメッセージの送信関係
import json
import requests

# 署名の検証関係
import base64
import hashlib
import hmac


# アクセストークンに関するclass
class AccessToken:
    def __init__(self):
        # .envをロード
        load_dotenv(override=True)
        # アクセストークンの破棄などで使い回す可能性があるのでこの時点でchannel_idを.envから読み込んでおく。
        self.channel_id = os.environ['channel_id']
        # 短期のアクセストークンの発行などで使い回す可能性があるのでこの時点でclient_secretを.envから読み込んでおく。
        self.client_secret = os.environ['client_secret']
        # よく使い回すのでインスタンス変数としておくとなんとなく便利
        self.base_domain = 'https://api.line.me'
        # 認証用uri
        self.auth_uri = f'{self.base_domain}/oauth2/v2.1'


    # jwt生成関数
    def encode_jwt(self, token_exp=60*60*24*30):
        # token_expをデフォルトで30日に指定
        # .envの内容を取得。
        private_key = {
                'alg':os.environ['alg'],
                'd':os.environ['d'],
                'dp':os.environ['dp'],
                'dq':os.environ['dq'],
                'e':os.environ['e'],
                'kty':os.environ['kty'],
                'n':os.environ['n'],
                'p':os.environ['p'],
                'q':os.environ['q'],
                'qi':os.environ['qi'],
                'use':os.environ['use']
                }

        # headerを以下の内容で指定
        headers = {
                'alg':'RS256',
                'typ':'JWT',
                'kid':os.environ['kid']
                }

        # payloadを以下の内容で指定
        payload = {
                'iss':self.channel_id,
                'sub':self.channel_id,
                'aud':f'{self.base_domain}/',
                'exp':int(time.time())+(60*30),
                'token_exp':token_exp
                }

        key = RSAAlgorithm.from_jwk(private_key)
        JWT = jwt.encode(payload, key, algorithm='RSA256', headers=headers, json_encoder=None)

        return JWT
    

    # チャネルアクセストークンv2.1の発行を行う関数
    def issue_access_token(self, JWT):
        # トークン発行のエンドポイントに各種パラメータをセットしてpostリクエストを行う。
        # ヘッダとボディは以下のように指定する。        
        uri = f'{self.auth_uri}/token'
        headers = {
                'Content-Type':'application/x-www-form-urlencoded'
                }
        data = {
                'grant_type':'client_credentials',
                'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion':JWT
                }

        r = requests.post(url=uri, headers=headers, data=data)
        r_json = r.json()

        # 生成に失敗したときのハンドリング。status_codeでバリデーションした方が良いかもしれない。
        if not 'error' in r_json:
            return r_json

        else:
            status_code = r.status_code
            r_json['status_code'] = r.status_code
            return r_json


# 署名の検証に関するclass
class VerifySignature(AccessToken):
    def __init__(self):
        # AccessToken()でprivate_keyを読み込んでいるので継承
        super().__init__()


    def verify_signature(self, l_signature, data):
        client_secret = self.client_secret
        # ボディのダイジェスト値を求めます。
        hash_ = hmac.new(client_secret.encode('utf-8'), data, hashlib.sha256).digest()
        # ダイジェスト値をBase64エンコードします。
        b_signature = base64.b64encode(hash_)
        # 署名をutf-8にデコード
        signature = b_signature.decode('utf-8')

        # リクエストボディとリクエストヘッダの署名が一致するかを確かめます。
        if l_signature == signature:
            return True

        else:
            return False


class Message(AccessToken):
    def __init__(self):
        super().__init__()
        # メッセージ送信用ドメイン
        self.msg_uri = f'{self.base_domain}/v2/bot/message'

    # メッセージ送信関数
    def send_message(self, access_token, message, send_type, reply_token):
        # 返信用メッセージの生成。
        # 同一reply_tokenに5個までメッセージを送信できる。
        # 今回はreply_token1つにつき1つのメッセージを返信する。
        content = [
                {
                    'type':'text',
                    'text':message
                    }
                ]

        # メッセージ送信用エンドポイントの指定
        uri = f'{self.msg_uri}/{send_type}'

        # アクセストークンをAutorizationのなかにBearer形式で指定
        headers = {
                'Content-Type':'application/json',
                'Authorization':f'Bearer {access_token}'
                }

        # 返信用のメッセージデータをreply_tokenと一緒に指定
        data = {
                'messages':content,
                'replyToken':reply_token
                }

        # メッセージの返信
        r = requests.post(url=uri, headers=headers, data=json.dumps(data))
        r_json = r.json()

        # エラーハンドリング
        if not 'error' in r_json:
            return r_json

        else:
            status_code = r.status_code
            r_json['status_code'] = r.status_code
            return r_json


    # 受信内容解析&返信実行関数
    def recieve(self, d_json):
        # d_jsonに含まれるeventsの内容を抽出する。
        events = d_json['events']
        # eventsの中には返信を行うのに重要なreply_tokenやメッセージの内容が含まれている場合がある。
        # 順番に返事が行えるようにreply_tokenを格納するlistを先に準備しておく。
        reply_tokens = list()
        # 複数の返信先にメッセージを返せるように返信用メッセージを格納するlistを先に準備しておく。
        msgs = list()
        # eventsの中身を一つずつ取り出す。
        for event in events:
            # reply_tokenを抽出してlistに格納
            reply_token = event['replyToken']
            reply_tokens.append(reply_token)
            # 受信したメッセージを抽出
            message_data = event['message']
            # 写真や動画の場合もあるので受信したメッセージの種類を抽出する。
            messege_type = message_data['type']
            # 受信内容がテキストメッセージならmessageに内容を格納
            if messege_type == 'text':
                message = message_data['text']
                msgs.append(message)
            else:
                # 今は一旦pass
                pass

        # 返信処理の実行
        for reply_token in reply_tokens:
            # index番号の取得
            index = reply_tokens.index(reply_token)
            # reply_tokenのindex番号に対応するmessageを取得
            msg = msgs[index]
            # access_tokenなどを引数にしてメッセージの返信処理関数を実行
            self.send_message(access_token, msg, 'reply', reply_token) 


# fastapiの実行
app = FastAPI()

# サーバー起動時にアクセストークンの発行を行う。
at = AccessToken()
# 今回は1時間の有効期限のアクセストークン
JWT = at.encode_jwt(token_exp=3600)
# アクセストークンの発行処理。
issued_at = at.issue_access_token(JWT)
access_token = issued_at['access_token']

# 署名の検証
vs = VerifySignature()

# メッセージ関係
msg = Message()

@app.post('/line-messaging-api/handle_request')
async def line(data:Request, x_line_signature:str=Header(None)):
    # Requestからbodyのデータを抽出
    b_data = await data.body()
    # 署名の検証
    l_signature = vs.verify_signature(x_line_signature, b_data)
    # 署名を検証し、一致しなければ`invalid_requests`を返す。
    if not l_signature:
        raise HTTPException(
                status_code=400,
                detail='invalid_requests',
                headers={'Content-type':'application/json'}
                )

    # Requestからjsonを抽出
    d_json = await data.json()
    msg.recieve(d_json)
    return {}

