/** Base64 encoder and decoder
*
* This class provided both encoding and decoding functions. These functions
* perform dynamic memory allocations to create space for the translated 
* response. It is up to the calling function to free the space when
* done with the translation.
*
* This code was derived from code found online that did not have any
* copyright or reference to its work.
*
* @code
* Base64 n;
*
* size_t encodedLen;
* char *encoded = n.Encode("This is the message", 20, &encodedLen);
* printf("Encoded message is {%s}\r\n", encoded);
* @endcode
*/

#ifndef BASE64_H
#define BASE64_H

#include <stdlib.h>
#include <string.h>

typedef unsigned int uint32_t;

//---------------------------------------------------------------------------
/**
* Check if string is base64 encoded
* This function is intentionally out of the class to be standalone
*/
bool IsBase64String(const char* s)
{
    if (!s) return false;

    int length = strlen(s);
    if (!length || length % 4 != 0) return false;

    for (int i = 0; i < length; i++)
    {
        char c = s[i];
        if ((c == '=' & i >= length-3) |
            (c == '/') |
            (c == '+') |
            (c >= '0' & c <= '9') | (c >= 'a' & c <= 'z') | (c >= 'A' & c <= 'Z') ) continue;
        return false;
    }
    return true;
}
//---------------------------------------------------------------------------
//---------------------------------------------------------------------------

class Base64
{
public:
    /** Constructor
    *
    */
    Base64();
    
    /** Destructor
    *
    * This will release memory that may have been allocated (when the Decode
    * function was called).
    */
    ~Base64();
    
    /** Encodes a string of information of a defined length
    *
    * The encoded information is considered a binary stream, therefore a length is provided
    * which is used to compute the amount of memory to allocate for the conversion.
    * 
    * @note The Decode method does not know how you are using it - if it is for text,
    *       it will not apply any null termination, unless that was part of the input.
    *
    * @param data is a pointer to the input binary stream.
    * @param input_length is the number of bytes to process.
    * @param output_length is a pointer to a size_t value into which is written the
    *        number of bytes in the output.
    *
    * @returns a pointer to the allocated block of memory holding the converted results.
    * @returns NULL if something went very wrong.
    */
    
    char *encoded_data;
    char *decoded_data;   

    char *Encode(const char *data, size_t input_length, size_t *output_len=NULL);
    
    /** Decodes a base64 encoded stream back into the original information.
    *
    * The information to decode is considered a base64 encoded stream. A length is
    * provided which is used to compute the amount of memory to allocate for the conversion.
    *
    * @note The Decode method does not know how you are using it - if it is for text,
    *       it will not apply any null termination, unless that was part of the input.
    *
    * @param data is a pointer to the encoded data to decode.
    * @param input_length is the number of bytes to process.
    * @param output_length is a pointer to a size_t value into which is written the
    *        number of bytes in the output.
    *
    * @returns a pointer to the allocated block of memory holding the converted results.
    * @returns NULL if something went very wrong.
    */
    char *Decode(const char *data, size_t input_length, size_t *output_len=NULL);
    
private:
    void build_decoding_table();
    char *decoding_table;
};
 
static const char encoding_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};
 
static const int mod_table[] = {0, 2, 1};
 
Base64::Base64()
{
    decoding_table = NULL;
    encoded_data = NULL;
    decoded_data = NULL;
}
 
Base64::~Base64()
{
    if (decoding_table)
        free(decoding_table);
    if (encoded_data)
        free(encoded_data);
    if (decoded_data)
        free(decoded_data);
}
 
 
char * Base64::Encode(const char *data, size_t input_length, size_t *output_len)
{
    size_t output_length;
    output_length = 4 * ((input_length + 2) / 3);
    //output_length = ((input_length - 1) / 3) * 4 + 4;
    if (output_len) *output_len=output_length;
    if (encoded_data)
        free(encoded_data);

    encoded_data = (char *)malloc(output_length+1); // often used for text, so add room for NULL
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[output_length - 1 - i] = '=';

    encoded_data[output_length] = '\0';    // as a courtesy to text users
    return encoded_data;
}
 

char * Base64::Decode(const char *data, size_t input_length, size_t *output_len)
{
    size_t output_length;

    if (input_length <= 0)
        return NULL;

    if (decoding_table == NULL)
        build_decoding_table();

    if (input_length % 4 != 0)
        return NULL;
    
    char c;
    for (int i = 0; i < input_length; i++)
    {
        c = data[i];
        if ((c == '=' & i >= input_length-3) |
            (c == '/') |
            (c == '+') |
            (c >= '0' & c <= '9') | (c >= 'a' & c <= 'z') | (c >= 'A' & c <= 'Z') )continue;
        return NULL;
    }

    output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (output_length)--;
    if (data[input_length - 2] == '=') (output_length)--;
    if (output_len) *output_len=output_length;

    if (decoded_data)
        free(decoded_data);
    decoded_data = (char *)malloc(output_length+1);  // often used for text, so add room for NULL
    if (decoded_data == NULL) 
        return NULL;
 
    for (unsigned int i = 0, j = 0; i < input_length;) {
 
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
 
        uint32_t triple = (sextet_a << 3 * 6)
                          + (sextet_b << 2 * 6)
                          + (sextet_c << 1 * 6)
                          + (sextet_d << 0 * 6);
 
        if (j < output_length)
            decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < output_length)
            decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < output_length) 
            decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
    decoded_data[output_length] = '\0';    // as a courtesy to text users
    return decoded_data;
}
 
 
void Base64::build_decoding_table()
{
    decoding_table = (char *)malloc(256);
 
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}

#endif // BASE64_H
  


// Base64 encoder and decoder without class
//
static const unsigned char base64_table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
unsigned char * base64_encode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	out = (unsigned char*)malloc(olen);
	if (out == NULL)
		return NULL;

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		//line_len += 4;
		if (line_len >= 72) {
			*pos++ = '\n';
			line_len = 0;
		}
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		//line_len += 4;
	}

	if (line_len)
		*pos++ = '\n';

	*pos = '\0';
	if (out_len)
		*out_len = pos - out;
	return out;
}


/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer.
 */
unsigned char * base64_decode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char dtable[256], *out, *pos, in[4], block[4], tmp;
	size_t i, count, olen;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table); i++)
		dtable[base64_table[i]] = i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count % 4)
		return NULL;

	olen = count / 4 * 3;
	pos = out = (unsigned char*)malloc(count);
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		in[count] = src[i];
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
		}
	}

	if (pos > out) {
		if (in[2] == '=')
			pos -= 2;
		else if (in[3] == '=')
			pos--;
	}

	*out_len = pos - out;
	return out;
}