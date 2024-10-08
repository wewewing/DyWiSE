#ifndef AURA_GGMNODE_H
#define AURA_GGMNODE_H

#include "../Util/CommonUtil.h"

class GGMNode
{
public:
    long index;
    int level;
    uint8_t key[AES_BLOCK_SIZE]{};

    GGMNode(long index, int level)
    {
        this->index = index;
        this->level = level;
    }

    GGMNode(long index, int level, uint8_t *key)
    {
        this->index = index;
        this->level = level;
        memcpy(this->key, key, AES_BLOCK_SIZE);
    }
};

#endif //AURA_GGMNODE_H
