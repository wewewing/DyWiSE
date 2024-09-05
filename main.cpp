#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <map>
#include "primitive.h"
#include <set>
#include <array>
#include <unordered_map>
#include "GGM/GGMTree.h"
#include <iomanip>
#include <chrono>
extern "C"
{
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
}
unsigned char derived_key1[16];
using namespace std; // 使用标准命名空间以便使用 cout、vector、string 等
struct EDBCELL {
    string D;
    string C;
    int uptime;
};
int get_level()
{
    return ceil(log2(958505));
}
struct StateCell
{
    std::string tk;
    int cntw;
};

int get_level();

enum DFCTOP
{
    DFCT_add = 0,
    DFCT_del
};
void compute_leaf_keys(unordered_map<long, string> &keys, const vector<GGMNode> &node_list, int level)
{
    for (GGMNode node: node_list)
    {
        for (int i = 0; i < pow(2, level - node.level); ++i)
        {
            int offset = ((node.index) << (level - node.level)) + i;
            uint8_t derive_key[AES_BLOCK_SIZE];
            memcpy(derive_key, node.key, AES_BLOCK_SIZE);
            GGMTree::derive_key_from_tree(derive_key, offset, 0, level - node.level);
            if (keys.find(offset) == keys.end())
            {
                string key_;
                key_.assign((const char *) derive_key, 16);
                keys[offset] = key_;
            }
        }
    }}
std::string stringToBinary(const std::string& input) {
    std::string result;

    // 处理keyword部分
    std::string keyword;
    size_t commaPos = input.find(',');
    if (commaPos != std::string::npos) {
        keyword = input.substr(0, commaPos);
    } else {
        keyword = input;
    }

    // 处理number部分
    std::string numberString;
    if (commaPos != std::string::npos) {
        numberString = input.substr(commaPos + 1);
    }

    // 将keyword部分转化为二进制字符串
    for (char c : keyword) {
        result += std::bitset<8>(c).to_string();
    }

    // 将number部分转换为16位二进制字符串
    int number = std::stoi(numberString);
    std::string numberBinary = std::bitset<16>(number).to_string(); // 修改为16位

    // 将keyword部分和number部分拼接在一起
    result += numberBinary;

    return result;
}
long binaryToLong(const std::string& binaryStr) {
    std::bitset<64> bitset(binaryStr);
    long k = bitset.to_ulong();
    return k;
}


int Trapdoor(std::string &K_out, std::string &L, std::string &MskD, std::string &MskC,
             const std::string &keyword,map<std::string,StateCell > &myMap,bn_t K)//int &cnt_w
{
    unsigned char buf[64];
    StateCell cell;
    string s;
    ep_t e_L, e_MskC, e_MskD;
    auto iter = myMap.find(keyword);

    // 检查关键字是否存在于 map 中
    if (iter != myMap.end()) {
        // 找到了关键字，通过迭代器获取对应的值
        cell = iter->second;
        // 使用 value 进行操作
    } else {
        std::cout << "关键字未找到！" << std::endl;
        return -1;
    }
    ep_new(e_L);
    ep_new(e_MskC);
    ep_new(e_MskD);

    s = cell.tk;
    Hash_H1(e_L, s);
    ep_mul(e_L, e_L, K);

    Hash_H2(e_MskD, s);
    ep_mul(e_MskD, e_MskD, K);

    Hash_G(e_MskC, s);
    ep_mul(e_MskC, e_MskC, K);

    bn_write_bin(buf, 32, K);
    K_out.assign((char *)buf, 32);

    ep_write_bin(buf, 33, e_L, 1);
    L.assign((char *)buf, 33);

    ep_write_bin(buf, 33, e_MskD, 1);
    MskD.assign((char *)buf, 33);

    ep_write_bin(buf, 33, e_MskC, 1);
    MskC.assign((char *)buf, 33);

    //cnt_w = cell.cntw;
    ep_free(e_L);
    ep_free(e_MskC);
    ep_free(e_tmp);
    ep_free(e_MskD);

    return 0;
}
int DataUpdate(std::string &L, std::string &D, std::string &C, DFCTOP op, const std::string &keyword,
               const std::string &id,map<std::string,StateCell > &myMap,bn_t K, bn_t K1)
{
    StateCell cell;
    unsigned char buf1[64];
    string tk1, s;
    ep_t e_L, e_D, e_C, e_tmp,f;
    string ss;

    ep_new(e_L);
    ep_new(e_D);
    ep_new(e_C);
    ep_new(e_tmp);
    auto iter = myMap.find(keyword);
    if (iter == myMap.end()) {
        RAND_bytes(buf1, 16);
        cell.tk.assign((char *)buf1, 16);
        cell.cntw = 0;
    }
    else{
        cell.tk=iter->second.tk;
        cell.cntw=iter->second.cntw;
    }
    cell.cntw += 1;

    RAND_bytes(buf1, 16);
    tk1.assign((char *)buf1, 16);

    Hash_H1(e_L, tk1);
    ep_mul(e_L, e_L, K);

    pi(e_D, cell.tk);
    pi_inv(ss,e_D);
    Hash_H2(e_tmp, tk1);
    ep_add(e_D, e_tmp, e_D);
    ep_mul(e_D, e_D, K);

    Hash_G(e_C, tk1);
    if (op == DFCT_add)
        s = "1" + id;
    else
        s = "0" + id;
    pi(e_tmp, s);
    ep_mul(e_tmp, e_tmp, K1);
    ep_mul(e_C, e_C, K);
    ep_add(e_C, e_C, e_tmp);

    ep_write_bin(buf1, 33, e_L, 1);
    L.assign((char *)buf1, 33);

    ep_write_bin(buf1, 33, e_D, 1);
    D.assign((char *)buf1, 33);

    ep_write_bin(buf1, 33, e_C, 1);
    C.assign((char *)buf1, 33);

    cell.tk = tk1;
    myMap[keyword] = cell;


    ep_free(e_L)
    ep_free(e_D);
    ep_free(e_C);
    ep_free(e_tmp);

    return 0;
}
void print_hex(const char* str, int length, std::ostream& output) {
    for (int i = 0; i < length; ++i) {
        output << std::hex << static_cast<int>(str[i]) << " ";
    }
    output << std::endl;
}
int findCharInArray(std::vector<string> arr, string target, int startIndex) {
    for (int i = startIndex; i < arr.size(); i++) {
        if (target== arr[i]) {
            return i; // Character found at index i
        }
    }
    return -1; // Character not found
}

// Function to find the minimum long key in the unordered_map
long findMinElement(const std::unordered_map<long, std::string>& umap) {
    long minKey = std::numeric_limits<long>::max();

    for (const auto& pair : umap) {
        if (pair.first < minKey) {
            minKey = pair.first;
        }
    }

    return minKey;
}
std::string store_hex(const void *data, int len) {
    const uint8_t *data_ = (const uint8_t *) data;
    std::ostringstream oss;
    for (int i = 0; i < len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data_[i]) << " ";
    }
    return oss.str();
}
void Search(std::vector<std::string> &result, const std::string &K_in, const std::string &L_in,
            const std::string &MskD_in, const std::string &MskC_in,const  map<std::string, EDBCELL> &DB,const bn_t &d,vector<vector<GGMNode>> character,vector<int>value,vector<int> e,vector<int> C,vector<vector<string>> matchmap)
{
    string L, MskD, MskC, tk, cip;
    unordered_map<long, string> keys;
    ep_t ele1, ele2;
    bn_t K;
    bn_new(K);
    string s1,s2;
    set<string> tmp;

    vector<unordered_map<long, string>> keyValuePairs;
    unsigned char buf[128];
    ep_new(ele1);
    ep_new(ele2);
    L = L_in;
    MskD = MskD_in;
    MskC = MskC_in;
    bn_read_bin(K, (const unsigned char *)K_in.c_str(), 32);
    for(int y=0;y<character.size();y++){
    compute_leaf_keys(keys, character[y], get_level());
    keyValuePairs.push_back(keys);
    keys.clear();
    }
    auto iter = DB.find(L);
    while (iter != DB.end()) {
        int i=iter->second.uptime;
        bool KK= false;
        vector<string> match;
        for(int j=0;j< keyValuePairs.size();j++) {
            int k=i+findMinElement(keyValuePairs[j]);
            auto iter1 = keyValuePairs[j].find(k);
            if (iter1 != keyValuePairs[j].end()) {
                string hex = store_hex(iter1->second.c_str(),16);
                match.push_back(hex);
            }
        }


        {
            int groupIndexA = 0;
            int groupIndexB = 0;
            bool F = false;
            // 遍历C数组
            for (int o = 0; o <C.size(); o++) {
                int groupLength = C[o];
                // 在B中查找A组的第一个字符
                int foundIndex = findCharInArray(matchmap[o], match[groupIndexA], groupIndexB);

                if (foundIndex == -1 || 0 > matchmap[o].size() - groupLength) {
                    break; // B中未找到字符或者B超出边界，匹配失败
                }
                if(e[groupIndexA]>0){
                    if(e[groupIndexA]-1!=foundIndex)
                        break;
                }

                int f = foundIndex;

                // 检查A组中的后续字符是否与B中的相应字符匹配
                for (int j = 1; j < groupLength; j++) {

                    string currentCharA = match[groupIndexA + j];
                    f++;

                    // 根据value数组的值调整f的位置
                    if (value[groupIndexA + j] != 1) {
                        f = f + value[groupIndexA + j] - 1;
                    }

                    string currentCharB = matchmap[o][f];

                    // 调用Test函数检查字符是否匹配
                    if ((currentCharA!= currentCharB)) {
                        F = true;
                        break; // 字符不匹配，匹配失败
                    }

                }
                if (e[match.size()-1]-1<0) {
                    for (int k = match.size()-1; k < C[C.size() - 1]; o--) {
                        if(match[k]!=matchmap[o][e[k]+matchmap[o].size()])
                            break;
                    }
                }
                if (F) {
                    o = o - 1;
                    groupIndexB = foundIndex + 1;
                    F = false;
                } else {
                    groupIndexA += groupLength;
                    groupIndexB = foundIndex + groupLength;
                }

            }

            KK= true; // 所有字符成功匹配
        }
        ep_read_bin(ele1, (const unsigned char *)iter->second.D.c_str(), 33);
        ep_read_bin(ele2, (const unsigned char *)MskD.c_str(), 33);
        ep_sub(ele1, ele1, ele2);
        ep_mul(ele1, ele1, d);
        pi_inv(tk, ele1);

        ep_read_bin(ele1, (const unsigned char *)iter->second.C.c_str(), 33);
        ep_read_bin(ele2, (const unsigned char *)MskC.c_str(), 33);
        ep_sub(ele1, ele1, ele2);
        ep_write_bin(buf, 33, ele1, 1);
        cip.assign((const char *)buf, 33);
        if(KK== true){
       result.emplace_back(cip);}

        cip = tk;
        Hash_H1(ele1, cip);
        ep_mul(ele1, ele1, K);
        ep_write_bin(buf, 33, ele1, 1);
        L.assign((const char *)buf, 33);

        Hash_H2(ele1, cip);
        ep_mul(ele1, ele1, K);
        ep_write_bin(buf, 33, ele1, 1);
        MskD.assign((const char *)buf, 33);

        Hash_G(ele1, cip);
        ep_mul(ele1, ele1, K);
        ep_write_bin(buf, 33, ele1, 1);
        MskC.assign((const char *)buf, 33);








        iter = DB.find(L);
    }
    bn_free(c);
    bn_free(e);
    bn_free(d);
    bn_free(ord);
    bn_free(K);
    ep_free(ele1);
    ep_free(ele2);

}


void ExC(const std::string &a,vector<string> &key_list,vector<int> &value_list) {

    std::string temp1;
    int index = 0;

    int temp3;
    int k = index;

    for (int j = 0; j < a.length(); j++) {
        temp1 = a.substr(j, 1);
        temp3 = j;
        key_list.push_back(temp1);
        value_list.push_back(temp3);
    }


}
void remove_duplicates(const std::vector<std::string> &key_list, std::vector<std::string> &unique_key_list) {
    std::set<std::string> seen;
    for (const auto &key : key_list) {
        if (seen.find(key) == seen.end()) {
            unique_key_list.push_back(key);
            seen.insert(key);
        }
    }
}
int DecryptResult(std::vector<std::string> &plain_out, const std::vector<std::string> &cipher_in,
                  const bn_t d1)
{
    ep_t ele;
    string s1, s2;
    set<string> tmp;
    for (int i = cipher_in.size()- 1; i >= 0; i--)
    {
        ep_read_bin(ele, (const unsigned char *)cipher_in[i].c_str(), 33);
        ep_mul(ele, ele, d1);
        pi_inv(s1, ele);
        s2.assign(s1.begin() + 1, s1.end());
        if (s1[0] == '1')
            tmp.emplace(s2);
        else
            tmp.erase(s2);
    }
    /*for (const std::string& value : tmp) {
        std::cout << value << std::endl;
    }*/
    for (auto &itr : tmp)
        plain_out.emplace_back(itr);

    ep_free(ele);
    bn_free(c);
    bn_free(e);
    bn_free(d);
    bn_free(ord);

    return 0;
}
// 处理输入字符串并返回整数向量的函数
vector<string> ExKeyword(const string& dirc) {
    ifstream file(dirc);
    vector<string> cutwords;

    if (file.is_open()) {
        string readLine;

        while (getline(file, readLine)) {
            regex regex("[^a-zA-Z]");
            sregex_token_iterator it(readLine.begin(), readLine.end(), regex, -1);
            sregex_token_iterator end;

            while (it != end) {
                string word = *it;
                if (word.length() > 5) {  // 过滤长度大于5的单词
                    cutwords.push_back(word);
                }
                ++it;
            }
        }

        file.close();
    } else {
        cout << "Failed to open the file." << endl;
    }

    return cutwords;
}
std::vector<int> ExFeature2(std::string a,vector<std::string> &character,std::vector<int> &value,vector<int> &e) {
    int i = 0;                             // 初始化计数变量
    int numm = 1;                          // 初始化连续字符计数变量
    // 在遇到 '*' 字符或字符串结尾之前遍历字符串
    while (i != a.length() && a[i] != '*') {
        std::string temp(1, a[i]);// 提取当前字符
        i++;                               // 移动到下一个字符
        if (temp == "?") {                 // 如果字符是 '?'
            numm++;                        // 增加连续字符计数
            continue;                      // 继续下一次迭代
        }
        e.push_back(i);// 存储连续字符的计数 start with 1
        character.push_back(temp);         // 将字符存储在向量中
        value.push_back(numm);
        numm = 1;                          // 重置连续字符计数
    }

    std::vector<std::string> array;        // 存储以 '*' 分隔的子字符串的向量
    size_t pos = i;                        // 初始化子字符串提取位置
    // 提取以 '*' 分隔的子字符串并将它们存储在数组中
    while (pos < a.length()) {
        pos = a.find('*', pos);            // 从 'pos' 开始查找 '*' 的位置
        if (pos != std::string::npos) {    // 如果找到了 '*'
            std::string str = a.substr(i, pos - i); // 提取子字符串
            if (!str.empty()) {            // 如果子字符串不为空
                array.push_back(str);      // 将子字符串存储在数组中
            }
            pos++;                        // 移过 '*' 字符
            i = pos;                      // 更新下一个子字符串的起始位置
        } else {
            std::string str = a.substr(i, a.length() - i); // 提取剩余的子字符串
            if (!str.empty()) {            // 如果子字符串不为空
                array.push_back(str);      // 将子字符串存储在数组中
            }
            break;                         // 如果到达字符串结尾，退出循环
        }
    }

    int num = 1;                           // 初始化连续字符计数变量
    std::vector<int> paragraph(array.size() + 1); // 存储段落大小的向量
    paragraph[0] = character.size();      // 存储初始字符向量的大小
    int para2 = character.size();         // 存储字符向量的初始大小

    // 处理数组中的每个子字符串
    for (size_t j = 0; j < array.size(); j++) {
        // 遍历子字符串中的每个字符
        size_t k;
        for (k = 0; k < array[j].length(); k++) {
            if (array[j][k] == '?') {      // 如果字符是 '?'
                num++;                     // 增加连续字符计数
                continue;                  // 继续下一次迭代
            }
            std::string temp(1, array[j][k]); // 提取当前字符
            character.push_back(temp);     // 将字符存储在向量中
            if (k == 0 && !character.empty()) { // 如果是第一个字符且字符向量不为空
                value.push_back(num);       // 存储连续字符的计数
            } else {
                value.push_back(num);       // 存储连续字符的计数
            }
            if ((a.back()!='*')&&(j==array.size()-1)){
                e.push_back(k-array[j].length());
            }
            else(e.push_back(0));// not prefix suffix  set it as 0
            num = 1;                       // 重置连续字符计数
        }
       /* // 如果是最后一个子字符串且以非 '?' 字符结尾，则将最后一个字符连续计数存储在 character 中
        if (j == array.size() - 1 &&  array.back().back() != '?') {
            character.back() += "||0"; // 将最后一个字符||0替换向量最后一个字符
        }*/
        paragraph[j + 1] = character.size() - para2; // 存储段落大小
        para2 = character.size();         // 更新下一个段落的起始位置
    }

   /* // 输出字符和值向量的内容
    cout << "Character: ";
    for (const auto& ch : character) {
        cout << ch << " ";
    }
    cout << endl;

    cout << "Value: ";
    for (const auto& val : value) {
        cout << val << " ";
    }
    cout << endl;
    cout << "e: ";
    for (const auto& vall : e) {
        cout << vall << " ";
    }
    cout << endl;*/

    return paragraph;                     // 返回包含段落大小的向量
}
void setup(bn_t &K, bn_t &K1,bn_t &d,bn_t &d1){
    core_init();
    ep_param_set(NIST_P256);
    bn_t ord,c1,e1,c, e;
    bn_new(c1);
    bn_new(e1);
    bn_new(d1);
    bn_new(c);
    bn_new(e);
    bn_new(d);
    bn_new(K);
    bn_new(K1);
    bn_new(ord);
    ep_curve_get_ord(ord);
    bn_rand_mod(K, ord);
    bn_rand_mod(K1, ord);
    bn_gcd_ext(c, d, e, K, ord);
    bn_gcd_ext(c1, d1, e1, K1, ord);
}


std::vector<string> extractDistinctCharacters(const std::string& input) {
    std::vector<string> distinctChars; // 存储不同的字符

    std::string uniqueChars; // 存储已经出现过的字符

    for (char c : input) {
        if (c != '*' && c != '?') { // 排除 "*" 和 "?"
            if (uniqueChars.find(c) == std::string::npos) { // 如果字符 c 在 uniqueChars 中不存在
                uniqueChars += c; // 将字符 c 添加到 uniqueChars 中
                distinctChars.push_back(std::string(1, c)); // 将字符 c 转换为 std::string，并添加到 distinctChars 中
            }
        }
    }

    return distinctChars; // 返回不同的字符
}
std::string findMinCntwString(const std::vector<std::string>& K, const std::map<std::string, StateCell>& myMap) {
    int minCntw = std::numeric_limits<int>::max();  // 初始化最小 cntw 值为一个较大的数
    std::string minCntwString;

    for (const auto& str : K) {
        if (myMap.count(str) > 0) {  // 检查字符串是否存在于 myMap 中
            const StateCell& cell = myMap.at(str);  // 获取对应的 StateCell 对象

            if (cell.cntw < minCntw) {
                minCntw = cell.cntw;
                minCntwString = str;
            }
        }
    }

    return minCntwString;
}
void dataupdate( vector<string> &key_list1,map<string, EDBCELL> &DB, int count,DFCTOP op, const std::string &keyword,const int &id,map<std::string,StateCell > &myMap,bn_t K, bn_t K1){
    string L1, D1, C1;

    vector<string> key_list;
    vector<int> value_list;
    unsigned char derived_key[16];
    std::vector<std::string> unique_key_list;
    ExC(keyword,key_list,value_list);
    remove_duplicates(key_list, unique_key_list);
    for(string chara:key_list){
        string chara1 = chara + ","+to_string(count);
        std::string binary = stringToBinary(chara1);
        //cout<<"x:"<<chara1<<" binary:"<<binary<<endl;
        long number = binaryToLong(binary);
        //cout<<" convert to number: "<<number<<endl;
        //string cip;
        memcpy(derived_key, derived_key1, 16);
        GGMTree::derive_key_from_tree(derived_key, number, 0);
        string temp1= store_hex(derived_key,16);
        key_list1.push_back(temp1);
    }
    map<int, vector<string>> matchMap;
    for (string chara:unique_key_list)
    {
        DataUpdate(L1, D1, C1, op, chara, "file-" + std::to_string(id),myMap,K,K1);
        DB[L1]={D1,C1,count};
    }
}
// 主函数
std::vector<std::string> extractStrings(const std::string& filePath) {
    std::vector<std::string> strings;
    std::ifstream file(filePath);

    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::string word;
            iss >> word;
            strings.push_back(word);
        }
        file.close();
    } else {
        std::cout << "Failed to open the file: " << filePath << std::endl;
    }

    return strings;
}
int main() {
    std::string filePath = "/home/winnie/CLionProjects/DFCT/3.txt";
    std::vector<std::string> keywords = extractStrings(filePath);
    auto starts = std::chrono::high_resolution_clock::now();
    vector<string> key_list1;
    vector<int> value_list;
    std::vector<std::string> unique_key_list;
    vector<vector<string>> matchmap;
    vector<long> remain_pos;
    vector<GGMNode> nodes_, remain_node;
    vector<array<unsigned char, 16>> vec;
    RAND_bytes(derived_key1, 16);
    vector<string> ks;
    vector<string> result;
    core_init();
    ep_param_set(NIST_P256);
    ep_t ele;
    bn_t K, K1,ord,c1,e1,d1,c, e0, d;
    bn_new(c1);
    bn_new(e0);
    bn_new(d1);
    bn_new(c);
    bn_new(e1);
    bn_new(d);
    bn_new(K);
    bn_new(K1);
    bn_new(ord);
    ep_curve_get_ord(ord);
    bn_rand_mod(K, ord);
    bn_rand_mod(K1, ord);
    bn_gcd_ext(c, d, e0, K, ord);
    bn_gcd_ext(c1, d1, e1, K1, ord);
    map<string, EDBCELL> DB;
    vector<string> plain_out;
    map<string, StateCell> myMap;

    for(int pp=0;pp<1000;pp++)
    {
        int count=0;
        dataupdate(key_list1,DB,count,DFCT_add,keywords[pp],count,myMap,K,K1);
        count=count+1;
        matchmap.push_back(key_list1);
        key_list1.clear();
    }
    std::string input = "h*"; // 输入字符串
    std::vector<std::string> character;    // 存储单个字符的向量
    std::vector<std::vector<GGMNode>> character_label;    // 存储单个字符的向量label
    std::vector<int> value;                // 存储相应计数的向量
    std::vector<int> e;// 存储相应计数的向量
    string K_,L2, MskD, MskC;
    std::vector<int> result1 = ExFeature2(input,character,value,e);
    string mincharacter = findMinCntwString(character, myMap);// 处理输入字符串
    Trapdoor(K_, L2, MskD, MskC, mincharacter,myMap,K);
    vector<GGMNode> nodes;
    for (size_t j = 0; j < character.size(); j++){
        for (int i = 0; i <matchmap.size(); i++){
            string character_ = character[j]+"," +to_string(i);
            std::string binary = stringToBinary(character_);
            long number = binaryToLong(binary);
            remain_pos.emplace_back(number);
        }
        for (long pos : remain_pos)
            nodes_.emplace_back(GGMNode(pos, GGMTree::get_level()));
        remain_node = GGMTree::min_coverage(nodes_);
        nodes.reserve(remain_node.size());
        for (auto &i : remain_node)
        {
            memcpy(i.key, derived_key1,16);
            GGMTree::derive_key_from_tree(i.key, i.index, 0, i.level);
            GGMNode n(i.index, i.level);

            memcpy(n.key, i.key, 16);
            nodes.emplace_back(n);
        }
        character_label.push_back(nodes);
        remain_pos.clear();
        remain_node.clear();
        nodes_.clear();
        nodes.clear();
    }
    //end trapdoor1   K_,L2,MskD,MskC; trapdoor character_label,value,e


    Search(result,K_,L2,MskD,MskC,DB,d,character_label,value,e,result1,matchmap);
    DecryptResult( plain_out,result,d1);
    for (auto &idd : plain_out)
        cout << idd << endl;
    cout << "totally find " << plain_out.size() << " ciphertexts" << endl;
    // 获取当前时间点
    plain_out.clear();
    result.clear();
    return 0; // 返回 0 表示执行成功
}
