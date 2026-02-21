#include <stdint.h>
#include <stdio.h>

uint32_t adler_32(const uint8_t* const data, const uint64_t size)
{
	uint16_t a = 1, b = 0;

	for (uint64_t i = 0; i < size; ++i)
	{
		a = (a + data[i]) % 65521;
		b = (a + b) % 65521;
	}

	uint32_t checksum = b;
	checksum <<= 16;
	checksum += a;

	return checksum;
}

uint16_t fletcher_16(const uint8_t* const data, const uint64_t size)
{
	uint16_t a = 0, b = 0;

	for (uint64_t i = 0; i < size; ++i)
	{
		a = (a + data[i]) % 255;
		b = (a + b) % 255;
	}

	return (b << 8) | a;
}

int main()
{
	for (char i = 32; i < 126; i++)
	{
		for (char j = 32; j < 126; j++)
		{
			for (char k = 32; k < 126; k++)
			{
				for (char x = 32; x < 126; x++)
				{
					const int pass_len = 8;

					char str1[] = { i, j, k, x, x, k, j, i, 0 };
					const uint32_t hash1 = adler_32((uint8_t*)str1, pass_len);
					const uint16_t hash2 = fletcher_16((uint8_t*)str1, pass_len);

					bool is_valid = true;
					for (int f = 0; f < pass_len; ++f)
					{
						is_valid &= str1[f] % 2 == 0;
						is_valid &= str1[f] > 32;
						is_valid &= str1[f] < 127;
					}

					// palindrome check
					is_valid &= str1[0] == str1[7];
					is_valid &= str1[1] == str1[6];
					is_valid &= str1[2] == str1[5];
					is_valid &= str1[3] == str1[4];

					// a small position dependent check
					uint32_t shift_checksum = 0;
					for (int a = 0; a < pass_len; ++a)
						shift_checksum += (str1[a]) << a;

					const uint32_t combined_hash = ((hash1 ^ hash2) * is_valid) ^ shift_checksum;

					if (combined_hash == 100806214 && is_valid)
						printf("[%s] = %d\n", str1, combined_hash);
				}
			}
		}
	}
}
