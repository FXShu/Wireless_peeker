#ifndef SHA1_I_H
#define SHA1_I_H

struct SHA1Context {
	u32 state[5];
	u32 count[2];
	unsigned char buffer[64];
};

//void SHA1Init(struct SHA1Context *context);
//void SHA1Update(struct SHA1Context *context, const void *data, u32 len);
//void SHA1Final(unsigned char digest[20], struct SHA1Context *context);
//void SHA1Transform(u32 state[5], const unsigned char buffer[64]);
#endif /* SHA1_I_H */
