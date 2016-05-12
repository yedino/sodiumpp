//
//  main.cpp
//  sodiumpp
//
//  Created by Ruben De Visscher on 02/08/14.
//  Copyright (c) 2014 Ruben De Visscher. All rights reserved.
//

#include <iostream>
#include <sodiumpp/sodiumpp.h>
#include <sodiumpp/locked_string.h>
#include <bandit/bandit.h>

using namespace sodiumpp;
using namespace bandit;

go_bandit([](){
    describe("z85", [](){
        box_secret_key box_sk;
        sign_secret_key sign_sk;
        
        it("can encode/decode box sk", [&](){
            encoded_bytes encoded = box_sk.get(encoding::z85);
            box_secret_key box_sk_decoded(box_sk.pk, encoded);
            AssertThat(box_sk_decoded.get().to_binary(), Equals(box_sk.get().to_binary()));
        });
        
        it("can encode/decode sign sk", [&](){
            encoded_bytes encoded = sign_sk.get(encoding::z85);
            sign_secret_key sign_sk_decoded(sign_sk.pk, encoded);
            AssertThat(sign_sk_decoded.get().to_binary(), Equals(sign_sk.get().to_binary()));
        });
    });
    
    describe("hex", [](){
        box_secret_key box_sk;
        sign_secret_key sign_sk;
        
        it("can encode/decode box sk", [&](){
            encoded_bytes encoded = box_sk.get(encoding::hex);
            box_secret_key box_sk_decoded(box_sk.pk, encoded);
            AssertThat(box_sk_decoded.get().to_binary(), Equals(box_sk.get().to_binary()));
        });
        
        it("can encode/decode sign sk", [&](){
            encoded_bytes encoded = sign_sk.get(encoding::hex);
            sign_secret_key sign_sk_decoded(sign_sk.pk, encoded);
            AssertThat(sign_sk_decoded.get().to_binary(), Equals(sign_sk.get().to_binary()));
        });
    });

    describe("nonce", [](){
        it("can increment basic", [&](){
            nonce64 n = nonce64(encoded_bytes("00000000000000000000000000000000", encoding::hex), encoded_bytes("0000000000000000", encoding::hex));
            AssertThat(n.get(encoding::hex).bytes, Equals("00000000000000000000000000000000" "0000000000000000"));
            n.increment();
            AssertThat(n.get(encoding::hex).bytes, Equals("00000000000000000000000000000000" "0000000000000002"));
        });        
        it("can increment with carry", [&](){
            nonce64 n = nonce64(encoded_bytes("00000000000000000000000000000000", encoding::hex), encoded_bytes("00fffffffffffffe", encoding::hex));
            AssertThat(n.get(encoding::hex).bytes, Equals("00000000000000000000000000000000" "00fffffffffffffe"));
            n.increment();
            AssertThat(n.get(encoding::hex).bytes, Equals("00000000000000000000000000000000" "0100000000000000"));

            n = nonce64(encoded_bytes("00000000000000000000000000000000", encoding::hex), encoded_bytes("00ffffffffffffff", encoding::hex));
            AssertThat(n.get(encoding::hex).bytes, Equals("00000000000000000000000000000000" "00ffffffffffffff"));
            n.increment();
            AssertThat(n.get(encoding::hex).bytes, Equals("00000000000000000000000000000000" "0100000000000001"));
        });
        it("can detect overflow", [&](){
            nonce64 n = nonce64(encoded_bytes("00000000000000000000000000000000", encoding::hex), encoded_bytes("fffffffffffffffe", encoding::hex));
            AssertThat(n.get(encoding::hex).bytes, Equals("00000000000000000000000000000000" "fffffffffffffffe"));
            n.increment();
            AssertThrows(std::overflow_error, n.get());
            AssertThrows(std::overflow_error, n.next());

            n = nonce64(encoded_bytes("00000000000000000000000000000000", encoding::hex), encoded_bytes("ffffffffffffffff", encoding::hex));
            AssertThat(n.get(encoding::hex).bytes, Equals("00000000000000000000000000000000" "ffffffffffffffff"));
            n.increment();
            AssertThrows(std::overflow_error, n.get());
            AssertThrows(std::overflow_error, n.next());
        });
    });

    describe("locked_string", [](){
        std::string data;
        before_each([&](){
            data = "abcd";
            data += char(0);
            data += "1234";
        });
        it("can move from not locked", [&](){
            const char * const source_data_ptr = &data[0];
            locked_string ls = locked_string::move_from_not_locked_string(std::move(data));
            AssertThat(source_data_ptr, Equals(&ls[0]));
        });
        it("can move from locked", [&](){
            const char *source_data_ptr = &data[0];
            sodiumpp::mlock(data);
            locked_string ls = locked_string::move_from_not_locked_string(std::move(data));
            AssertThat(source_data_ptr, Equals(&ls[0]));
        });
        it("can create copy", [&](){
            locked_string ls(data);
            AssertThat(ls.size(), Equals(data.size()));
            AssertThat(sodium_memcmp(ls.data(), data.data(), data.size()), Equals(0));
            AssertThat(ls.size(), Equals(data.size()));
        });
        it("can compare", [&](){
            locked_string ls1(data);
            locked_string ls2(data);
            AssertThat(ls1==ls2, Equals(true));
            AssertThat(ls1!=ls2, Equals(false));
            ls2.back() = 'z';
            AssertThat(ls1==ls2, Equals(false));
            AssertThat(ls1!=ls2, Equals(true));
        });
        it("can copy", [&](){
            locked_string ls(data);
            locked_string ls2(ls);
            locked_string ls3;
            ls3 = ls2;
            ls = ls;
            AssertThat(ls == ls2, Equals(true));
            AssertThat(ls2 == ls3, Equals(true));
        });
        it("can move", [&](){
              locked_string ls(data);
              const char* const ls_data_ptr = &ls[0];
              locked_string ls2(std::move(ls)); // move constructor
              AssertThat(ls.size() == 0, Equals(true));
              const char* const ls2_data_ptr = &ls2[0];
              AssertThat(ls_data_ptr == ls2_data_ptr, Equals(true));
              locked_string ls3;
              ls3 = std::move(ls2); // move assigment
              const char* const ls3_data_ptr = &ls3[0];
              AssertThat(ls2_data_ptr == ls3_data_ptr, Equals(true));
        });
    });
});

int main(int argc, char ** argv) {
    return bandit::run(argc, argv);
}
