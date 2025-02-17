class GMult: #Galois alanında (GF(2^8)) çarpma işlemini gerçekleştirir.Bu işlem AES algoritmasında MixColumns aşamasında kullanılır.
    @staticmethod
    def multiply(a, b): # Amaç iki 8-bit değeri Galois alanında çarpar.
        result = 0 # Çarpım sonucunu saklar.
        for _ in range(8): # çarpma işlemini 8 bit üzerinde tekrarlar.
            if b & 1: # eğer b'nin en düşük biti 1 ise , a değerini result ile XOR'lar.
                result ^= a
            high_bit_set = a & 0x80 # anın en bütük biti 1 mi kontrol eder.
            a <<= 1 #a yı sola kaydırır.
            if high_bit_set: # eğer en yüksek bit set edilmişse, a'yı 0x1b XOR yapılır.
                a ^= 0x1b
            b >>= 1 # b'yi kaydırarark sıradaki bite gider.
        return result & 0xFF # Sonucu 8-bit olarak döndürür.

class AES:
    Nb = 4  # AES' deki blok boyutu ( 4 adet 32-bit kelime)

    S_BOX = [ # Şifreleme sırasında kullanılan sabit bir alt bayt tablosu.
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    ]

    def __init__(self, key): # Amaç: AES nesnesini oluşturur ve anahtar genişletmesini başlatır.
        key_size = len(key) # Girilen anahtar uzunluğunu alır.
        if key_size == 16:  #  128-bit key
            self.Nk = 4 # kelime uzunluğu 
            self.Nr = 10 # kaç şifreleme veya çözme turu yapılacağını ifade eder
        elif key_size == 24:  # 192-bit key
            self.Nk = 6 
            self.Nr = 12
        elif key_size == 32:  # 256-bit key
            self.Nk = 8
            self.Nr = 14
        else:
            raise ValueError(f"Invalid key size: {key_size}")

        self.w = bytearray(4 * self.Nb * (self.Nr + 1))  # Genişletilmiş anahtarı tutan bellek.Nb:kelime sayısı Nr: tur sayısı
        self.key_expansion(key)

    def key_expansion(self, key): # Amaç:AES için anahtar genişletme işlemi. 
        temp = bytearray(4) #Ara değerleri tutar.
        i = 0
                                 
        while i < 4 * self.Nk: # Bu döngü,anahtar genişletme işleminin başlangıcını oluşturur. Amaç:İlk Nk kelimeyi genişletilmiş anahtara kopyalamak. örneğin 128-bit bir anahtar için döngü 16 byte boyunca çalışır.
            self.w[i] = key[i] #başlangıçtaki anahtarın ilgili byte'ını alır.
            i += 1 # her döngüde bir artırılarak tüm Nk kelimesi doldurulur.

        i = self.Nk #self.Nb*(self.nr +1) genişletilmiş anahtarın uzunluğu şu formülle hesaplanır.
        while i < self.Nb * (self.Nr + 1): # self.Nb: AES algoritmasından , blok boyutunu 32-bit kelimeler cinsinden ifade eder.(Standart olarak Nb=4).self.Nr: Şifreleme turları(rounds) sayısıdır. Bu değer , anahtar uzunluğuna bağlı olarak değişir.Amaç: Genişletilmiş anahtarın kalan kıısmlarını üretmek.
            temp[:] = self.w[4 * (i - 1):4 * i]#temp önceki kelimenin bir kopyasıdır. Bu , anahtar genişletme işlemi sırasında kullanılan geçici bir tampondur.
            #i-1'inci kelimenin byte'larını alır.Örneğin i=5 ise 4*(i-1)=16, 4*i=20 bu 16-19 byte'ları alır.

            if i % self.Nk == 0: #AES Key Schedule önemli bir parçasıdır.şart:Eğer i Nk'nin tam katsayıysa:
                self.rot_word(temp) #Rotasyon işlemi:temp içindeki bytleri bir sola kaydır.[0x01,0x02,0x03,0x04] > [0x03,0x04,0x01]
                self.sub_word(temp) # temp'in her byte'ına S-box uygulanır.
                rcon = self.rcon(i // self.Nk) # her tur için sabit bir değerdir.Bu değer, rcon tablosundan alınır.
                temp = bytearray(x ^ y for x, y in zip(temp, rcon)) # temp ve rcon byye-byte XOR'lanır.Bu tur sabitini anahtara ekler.
            elif self.Nk > 6 and i % self.Nk == 4: # (192 bit veyaz 256 bit anahtar ) ve self.Nk==4 ise
                self.sub_word(temp) # temp içindeki byte'lara sadece s_Box dönüşümü uygulanır. Bu ek adım, daha uxun anahtarlar için ekstra güvenlik sağlar.

            for j in range(4): # yeni genişletilmiş anahtarı hesaba katar.
                self.w[4 * i + j] = self.w[4 * (i - self.Nk) + j] ^ temp[j]
                # Nk kelime geriye giderek ilgili byte alınır.temp[j] ile XOR'lanır ve yeni kelime üretilir.
            i += 1

    def rcon(self, i): # Amaç:Her şifreleme turu için sabit bir değer döndürmak. 
        R = [1, 0, 0, 0] #İlk tur için sabit başlangıç değeri.İlk bayte olarak 1, diğerleri 0.
        for _ in range(1, i):
            R[0] = GMult.multiply(R[0], 0x02) # Galois alanında çarpma
        return R

    def rot_word(self, word):# amaç: verilen bir kelimenin döndürülmesi
        word.append(word.pop(0)) # ilk byteyi listenin sonuna ekler.

    def sub_word(self, word): # verilen kelimenin her byte'ına S_Box tablosu kullanılarak dönüşüm uygulanması. 
        for i in range(4):
            word[i] = self.S_BOX[word[i]]# sabit bir tablo olup her byte için yerine geçecek bir değer döndürür. Bu ,AES'in Subbytes adlı verilen güvenlik adımının bir parçasıdır.

    def encrypt(self, plaintext): #temel şifreleme işlemi

        if isinstance(plaintext, bytes):#giriş olarak verilen veri(plaintext) byte tipine dönüştürülür.
            plaintext = bytearray(plaintext) 

        state = [bytearray(plaintext[i::4]) for i in range(4)]#Amaç: Şifreleme işlmeleri için bir state matrisi oluşturmak.State matrisi 4x4'lük bir byte AES, bu matris üzerinde çalışılır.
        self.add_round_key(state, 0) #ilk olarak ,düz metne başlangıç tur anahtarı eklenir.
        # add_round_key her byte,ilgili anahtar byte' ile XOR işlemine tabi tutulur.Bu ,şifreleme işleminin ilk adımıdır.


        for round in range(1, self.Nr): #her turda bu dört adım vardır.
            self.sub_bytes(state)# S-Box ile her byte üzerinden dönüşüm yapılır.
            self.shift_rows(state)#Her satır belirli bir miktarda sola kaydırılır.
            self.mix_columns(state)#her satır galois alanında matris çarpımı ile krşılaştırılır.
            self.add_round_key(state, round)#Durum matrisine ilgili tur anahtarı eklenir(XOR işlemi)

        #busarı son tur ve son turda mizColumns uygulanmaz.
        self.sub_bytes(state)
        self.shift_rows(state)
        self.add_round_key(state, self.Nr)


        result = bytearray()# Durum matrisini orjinal byte düzenine dönüştürmek. Sonuç: Şifrelenmiş metin(ciphertext) elde edilir.
        for i in range(4):
            for j in range(4):
                result.append(state[j][i])
        return bytes(result)

    def decrypt(self, ciphertext):#şifrelenmiş metni çzöerek düzmetin elde etmek
        
        if isinstance(ciphertext, bytes):# eğer ciphertext bayt veri olarak verilmişse bunu değiştirilebilir bir veri türü olan bytearray'e dönüştürüyoruz. Böylece elemanlarını değiştirebiliriz.
            ciphertext = bytearray(ciphertext)

        state = [bytearray(ciphertext[i::4]) for i in range(4)] #4x4lük state matrisi oluşturulur.
        #ciphertext[i::4] ile ciphertext içerisindeki elemanlar 4'er adım atlayarak alınır.Bu işlem sütun bazlı bir matris oluşturmaya yarar. Her sütun byte tipinde saklanır. 
        
        self.add_round_key(state, self.Nr)#ilk adım olarak son tur anahtarı(round key) ile xOR işlemi uygulanır. Bu şifreleme sırasında yapılan işlemi geri alır.
        
        for round in range(self.Nr - 1, 0, -1): #şifreleme işlemi boyunca yapılan turları(rounds) tersine çeviririz.
            self.inv_shift_rows(state)#satırları şifreleme sırasında kaydırıldıysa ,burada tersine kaydırılır.
            self.inv_sub_bytes(state)#şifreleme sırasında kullanılan s-box ile bytler dönüştürülmüştü .Burada bu işlem tersine çevrilir.
            self.add_round_key(state, round)#tur anhatarı ile tekrar XOR işlemi yapılır.Bu , şifreleem sırasında yapılan XOR işlemini geri alır.
            self.inv_mix_columns(state)#şifrelemenin esnasında yapılan sütun karıştırılmasının tersine karıştırma yapar.Bu işlem Galois alanında matematiksel çarpma ve toplma ile gerçekleştirilir.
            #şifrelemede sıra mixcolumns,shiftrows,subbytes,addroundkey sırasındadır .Şifre çözmede ise bu sıranın tam tersi sırada yapılır.
        
        #son turda ıncmixcolumns işlenmez çünkü şifrelemede de  yok.
        self.inv_shift_rows(state) #ters kaydırma
        self.inv_sub_bytes(state) #ters S-box
        self.add_round_key(state, 0) #ilk tur anahtarıyla XOR
        
        result = bytearray() #state matrisini düz bir veri yapısına ddönüştürürüz.Matris sütun sütun okunduğu için,her sütundakş elemanları sırasıyle result adlı bir bytearray yapısına eklenir.
        for i in range(4):
            for j in range(4):
                result.append(state[j][i])
        return bytes(result) #sonuç bytes formatına döndürülür.

    def add_round_key(self, state, round):# state ile tur anahtarı matrisinin elemanları XOR işlemine tabi tutulur.
        start = round * 4 * self.Nb
        for i in range(4):
            for j in range(self.Nb):
                state[i][j] ^= self.w[start + i + 4 * j]#self.w amahtar matrisidir.Start ise bu tur için anahtar matrisinden başlanacak indisi belirler.

    def sub_bytes(self, state):
        for i in range(4):
            for j in range(self.Nb):
                state[i][j] = self.S_BOX[state[i][j]]

    def shift_rows(self, state):
        for i in range(1, 4):
            state[i] = state[i][i:] + state[i][:i]

    def mix_columns(self, state):
        for j in range(self.Nb):#Nb sütun sayısı ^operatörü XOR işlemini temsil eder.
            col = [state[i][j] for i in range(4)]
            state[0][j] = GMult.multiply(col[0], 2) ^ GMult.multiply(col[1], 3) ^ col[2] ^ col[3]
            state[1][j] = col[0] ^ GMult.multiply(col[1], 2) ^ GMult.multiply(col[2], 3) ^ col[3]
            state[2][j] = col[0] ^ col[1] ^ GMult.multiply(col[2], 2) ^ GMult.multiply(col[3], 3)
            state[3][j] = GMult.multiply(col[0], 3) ^ col[1] ^ col[2] ^ GMult.multiply(col[3], 2)



    INV_S_BOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]

    def inv_sub_bytes(self, state):#her bir byte ters S-BOX kullanılarak dönüştürülür.
        """Ters SubBytes operasyonu"""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.INV_S_BOX[state[i][j]]

    def inv_shift_rows(self, state):#şifrelemede kaydırılan satırlar, burada tersine kaydırılır.
        """Ters ShiftRows operasyonu"""
        for i in range(1, 4):
            state[i] = state[i][-i:] + state[i][:-i]

    def inv_mix_columns(self, state):
        """Ters MixColumns operasyonu"""
        for j in range(4): #her sütun ters karıştırma matrisi kullanılarak dönüştürülür.
            col = [state[i][j] for i in range(4)]
            
            # Ters mix column matrisi: [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]
            state[0][j] = (GMult.multiply(col[0], 14) ^ 
                          GMult.multiply(col[1], 11) ^ 
                          GMult.multiply(col[2], 13) ^ 
                          GMult.multiply(col[3], 9))
            
            state[1][j] = (GMult.multiply(col[0], 9) ^ 
                          GMult.multiply(col[1], 14) ^ 
                          GMult.multiply(col[2], 11) ^ 
                          GMult.multiply(col[3], 13))
            
            state[2][j] = (GMult.multiply(col[0], 13) ^ 
                          GMult.multiply(col[1], 9) ^ 
                          GMult.multiply(col[2], 14) ^ 
                          GMult.multiply(col[3], 11))
            
            state[3][j] = (GMult.multiply(col[0], 11) ^ 
                          GMult.multiply(col[1], 13) ^ 
                          GMult.multiply(col[2], 9) ^ 
                          GMult.multiply(col[3], 14))

    def decrypt(self, ciphertext):
        # bytes'ı bytearray'e çeviriyoruz
        if isinstance(ciphertext, bytes):
            ciphertext = bytearray(ciphertext)
            
        # State matrisini bytearray listesi olarak oluşturuyoruz
        state = [bytearray(ciphertext[i::4]) for i in range(4)]
        
        self.add_round_key(state, self.Nr)
        
        for round in range(self.Nr - 1, 0, -1):
            self.inv_shift_rows(state)
            self.inv_sub_bytes(state)
            self.add_round_key(state, round)
            self.inv_mix_columns(state)
        
        self.inv_shift_rows(state)
        self.inv_sub_bytes(state)
        self.add_round_key(state, 0)
        
        # Sonucu bytes olarak döndürüyoruz
        result = bytearray()
        for i in range(4):
            for j in range(4):
                result.append(state[j][i])
        return bytes(result)