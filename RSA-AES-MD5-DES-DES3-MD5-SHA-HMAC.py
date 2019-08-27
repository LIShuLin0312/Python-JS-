import base64
导入 rsa
来自 Crypto.Cipher 导入 AES
来自 Crypto.PublicKey 导入 RSA
来自 pyDes import des，CBC，PAD_PKCS5
来自 Crypto.Cipher 导入 DES3
import hashlib
导入 hmac


class  USE_AES：
    “””
    AES
    除了MODE_SIV模式key长度为：32,48或64，
    其余键长度为16,24或32
    详细见AES内部文档
    CBC模式传入IV参数
    本例使用常用的ECB模式
    “””

    def  __init__（self，key）：
        如果 len（键）>  32：
            key = key [：32 ]
        self .key =  self .to_16（key）

    def  to_16（self，key）：
        “””
        转为16倍数的字节数据
        ：param键：
        ：返回：
        “””
        key =  bytes（key，encoding = “ utf8 ”）
        而 len（键）％ 16  ！=  0：
            键+ =  b ' \ 0 '
        返回键   ＃返回字节

    高清 AES（个体经营）：
        返回 AES。新的（自 .KEY，AES。MODE_ECB）＃初始化加密器

    def  encrypt（self，text）：
        aes =  self .aes（）
        return  str（base64.encodebytes（aes.encrypt（self .to_16（text））），
                   encoding = ' utf8 '）.replace（' \ n '，' '）   ＃加密

    def  decodebytes（self，text）：
        aes =  self .aes（）
        return  str（aes.decrypt（base64.decodebytes（bytes（
            text，encoding = ' utf8 '）））。rstrip（b ' \ 0 '）。decode（“ utf8 ”））   ＃解密


class  USE_RSA：
    “””
    生成密钥可保存的.pem格式文件
    1024位的证书，加密时最大支持117个字节，解密时为128;
    2048位的证书，加密时最大支持245个字节，解密时为256。
    加密大文件时需要先用AES或者DES加密，再用RSA加密密钥，详细见文档
    文档：HTTPS：//stuvel.eu/files/python-rsa-doc/usage.html#generating-keys
    “””
    def  __init __（self，number = 1024）：
        “””
        ：param number：公司，私钥
        “””
        self .pubkey，self .privkey = rsa.newkeys（number）

    def  rsaEncrypt（self，text）：
        “””
        ：param test：str
        ：return：bytes
        “””
        content = text.encode（' utf-8 '）
        crypto = rsa.encrypt（内容，自我 .pubkey）
        返回加密
    
    def  rsaDecrypt（self，text）：
        “””
        ：param text：bytes 
        ：return：str
        “””
        content = rsa.decrypt（text，self .privkey）
        con = content.decode（' utf-8 '）
        返回 CON
        
    def  savePem（self，path_name，text）：
        “””
        ：param path_name：保存路径
        ：param text：str
        ：回归：字节
        “””
        如果 “ PEM ” 在 path_name.upper（）：
            path_name = path_name [：- 4 ]
        与 开放（' {}的.pem ' .format（路径名），'体重'）为 F：
            f.write（text.save_pkcs1（））

    def  readPem（self，path_name，key_type）：
        “””
        ：param path_name：密钥文件
        ：param key_type：类型 
        ：返回： 
        “””
        如果 key_type 中有' pubkey ' ：
            self .pubkey = rsa.PublicKey.load_pkcs1（path_name）
        否则：
            self .privkey = rsa.PublicKey.load_pkcs1（path_name）
        返回 True

    def  sign（self，message，priv_key = None，hash_method = ' SHA-1 '）：
        “””
        生成明文的哈希签名以便还原后对照
        ：param message：str
        ：param priv_key：
        ：param hash_method：哈希的模式
        ：返回：
        “””
        if  None  == priv_key：
            priv_key =  self .privkey
        return rsa.sign（message.encode（），priv_key，hash_method）

    def  checkSign（self，mess，result，pubkey = None）：
        “””
        验证签名：传入解密后明文，签名，公钥，验证成功返回哈希方法，失败则报错
        ：param mess：str
        ：param result：bytes
        ：param pubkey： 
        ：return：str
        “””
        if  None  == pubkey：
            pubkey =  self .privkey
        尝试：
            result = rsa.verify（mess，result，pubkey）
            返回结果
        除了：
            返回 False


 USE_DES 类：
    “””
    des（键，[mode]，[IV]，[pad]，[pad mode]）
    关键：必须正好8字节
    模式（模式）：ECB，CBC
    IV：CBC模式中必须提供长8字节
    垫：填充字符
    padmode：加密填充模式PAD_NORMAL或PAD_PKCS5
    “””
    def  __init__（self，key，iv）：
        如果 不是 isinstance（键，字节）：
            key =  bytes（key，encoding = “ utf8 ”）
        如果 不是 isinstance（iv，bytes）：
            iv =  字节（iv，encoding = “ utf8 ”）
        self .key = key
        自我 .iv = iv

    def  encrypt（self，text）：
        “””
        DES加密
        ：param text：原始字符串
        ：return：加密后字符串，字节
        “””
        如果 不是 isinstance（文本，字节）：
            text =  bytes（text，“ utf-8 ”）
        secret_key =  self .key
        iv =  self .iv
        k = des（secret_key，CBC，iv，pad = None，padmode = PAD_PKCS5）
        en = k.encrypt（text，padmode = PAD_PKCS5）
        返回 en

    def  descrypt（self，text）：
        “””
        DES解密
        ：param text：加密后的字符串，bytes
        ：return：解密后的字符串
        “””
        secret_key =  self .key
        iv =  self .iv
        k = des（secret_key，CBC，iv，pad = None，padmode = PAD_PKCS5）
        de = k.decrypt（text，padmode = PAD_PKCS5）
        return de.decode（）


class  USE_DES3：
    “””
    新的（键，模式，* args，** kwargs）
    关键：必须8个字节倍数介于16-24
    模式：
    IV：初始化向量适用于MODE_CBC，MODE_CFB，MODE_OFB，MODE_OPENPGP，4种模式
        ``MODE_CBC``，``MODE_CFB``和``MODE_OFB``长度为8字节
        ```MODE_OPENPGP```加密时8个字节解密时10bytes
        未提供默认随机生成
    nonce：仅在``MODE_EAX``和``MODE_CTR``模式中使用
            ``MODE_EAX``建议16字节
            ``MODE_CTR``建议[0,7]长度
            未提供则随机生成
    segment_size：分段大小，仅在``MODE_CFB``模式中使用，长度为8倍数，未指定则默认为8
    mac_len：适用``MODE_EAX``模式，身份验证标记的长度（字节），它不能超过8（默认值）
    initial_value：适用```MODE_CTR```，计数器的初始值计数器块默认为** 0 **。
    “””
    def  __init__（self，key）：
        self .key = key
        self .mode =  DES3。MODE_ECB

    def  encrypt（self，text）：
        “””
        传入明文
        ：param text：bytes类型，长度是KEY的倍数
        ：返回：
        “””
        如果 不是 isinstance（文本，字节）：
            text =  bytes（text，' utf-8 '）
        x =  len（文本）％ 8
        text = text + b ' \ 0 ' * x
        cryptor =  DES3 .new（self .key，self .mode ）
        密文= cryptor.encrypt（文本）
        返回密文

    def  decrypt（self，text）：
        cryptor =  DES3 .new（self .key，self .mode ）
        plain_text = cryptor.decrypt（text）
        st =  str（plain_text.decode（“ utf-8 ”））。rstrip（' \ 0 '）
        返回圣


def  USE_MD5（测试）：
    如果 不是 isinstance（测试，字节）：
        test =  bytes（test，' utf-8 '）
    m = hashlib.md5（）
    m.update（测试）
    返回 m.hexdigest（）


def  USE_HMAC（密钥，文本）：
    如果 不是 isinstance（键，字节）：
        key =  bytes（key，' utf-8 '）
    如果 不是 isinstance（文本，字节）：
        text =  bytes（text，' utf-8 '）
    h = hmac.new（key，text，digestmod = ' MD5 '）
    返回 h.hexdigest（）


def  USE_SHA（文字）：
    如果 不是 isinstance（文本，字节）：
        text =  bytes（text，' utf-8 '）
    sha = hashlib.sha1（文本）
    加密= sha.hexdigest（）
    返回加密


如果 __name__  ==  ' __main__ '：
    aes_test = USE_AES（“ assssssssdfasasasasa ”）
    a = aes_test.encrypt（“测试”）
    b = aes_test.decodebytes（a）
    rsa_test = USE_RSA（）
    a = rsa_test.rsaEncrypt（“测试加密”）
    b = rsa_test.rsaDecrypt（a）
    des_test = USE_DES（b “ 12345678 ”，b “ 12345678 ”）
    a = des_test.encrypt（“测试加密”）
    b = des_test.descrypt（a）
    des3_test = USE_DES3（b “ 123456789qazxswe ”）
    a = des3_test.encrypt（“测试加密”）
    b = des3_test.decrypt（a）
    md5_test = USE_MD5（“测试签名”）
    hmac_test = USE_HMAC（“ 123456 ”，“测试”）
    sha_test = USE_SHA（“测试加密”）
