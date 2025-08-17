package com.hash;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Md5 {
	
	//rotation table
	private static final int[] S = {
		    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
		    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
		    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
		    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
		};
	
	//sin(i) table
	private static final int[] INT_T = {
		    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
		};
	
	public Md5() {}
	
	public String digest(byte[] bytes) {
		byte[] buffer = appendPaddingBitsAndSize(bytes);
		//Each 512-bit block (64 bytes) is 16 words of 32 bits each
		int N = buffer.length / 64;

		byte[] A = ByteBuffer.allocate(4).putInt(0x67452301).array();
		byte[] B = ByteBuffer.allocate(4).putInt(0xefcdab89).array();
		byte[] C = ByteBuffer.allocate(4).putInt(0x98badcfe).array();
		byte[] D = ByteBuffer.allocate(4).putInt(0x10325476).array();

		byte[] AA = A.clone();
		byte[] BB = B.clone();
		byte[] CC = C.clone();
		byte[] DD = D.clone();

		//Number of blocks (512 bits) created loop
		for(int block=0;block<N;block++) {
			int nextWord = 0;

			for(int i=0;i<64;i++) {
				nextWord = selectNextWord(i);
				//Because the operations done are considering BIG_ENDIAN the buffer gets [3,2,1,0]
				byte[] bufferInput = new byte[] {
						(byte) buffer[64*block + 4*nextWord + 3], 
						(byte) buffer[64*block + 4*nextWord + 2], 
						(byte) buffer[64*block + 4*nextWord + 1], 
						(byte) buffer[64*block + 4*nextWord + 0]
					};
				byte[] result = F(B, C, D, i);
				byte[] result1 = add(A, result);
				byte[] result2 = add(result1, bufferInput);
				byte[] result3 = add(result2, getTTableValue(i));
				byte[] finalResult = add(leftRotate(result3, S[i]), B);
				A = D.clone();
				D = C.clone();
				C = B.clone();
				B = finalResult.clone();
			}
			
			A = add(A, AA);
			B = add(B, BB);
			C = add(C, CC);
			D = add(D, DD);
			
			AA = A.clone();
			BB = B.clone();
			CC = C.clone();
			DD = D.clone();
		}

		//Because the final hash in MD5 is LITTLE_ENDIAN
		//the bytes are inverted from BIG to LITTLE
		byte[] hash = new byte[] {
				(byte) A[3], (byte) A[2], (byte) A[1], (byte) A[0],
				(byte) B[3], (byte) B[2], (byte) B[1], (byte) B[0],
				(byte) C[3], (byte) C[2], (byte) C[1], (byte) C[0],
				(byte) D[3], (byte) D[2], (byte) D[1], (byte) D[0],
			};
		return bytesToString(hash);
	}
	
	private String bytesToString(byte[] bytes) {
	    StringBuilder sb = new StringBuilder();
	    for (byte b : bytes) {
	        sb.append(String.format("%02X", b));
	    }
	    return sb.toString();
	}

	private byte[] appendPaddingBitsAndSize(byte[] bytes) {
		//512bits = 64 bytes -- 448bits = 56 bytes
		int mod = (bytes.length + 1) % 64;
		int blocks = Math.ceilDiv((bytes.length + 1), 64);
		//if there are more than 56 bytes left it'll be needed 1 extra block
		if(mod > 56) {
			blocks++;
		}
		ByteBuffer buffer = ByteBuffer.allocate(64*blocks);
		//put byte array in buffer
		buffer.put(bytes);
		//add 1 in the end of byte array
		buffer.put((byte) 10000000);
		//add the size (as bits) in final 8 bytes LITTLE_ENDIAN order
		buffer.order(ByteOrder.LITTLE_ENDIAN).putLong(64*blocks - 8, (long) bytes.length * 8);
		return buffer.array();
	}
	
	//Select the next word to be processed from 16 words
	private int selectNextWord(int i) {
		//First round 
		if(0<=i && i<=15) {
			return i%16;
		//Second round
		} else if (16<=i && i<=31) {
			return (5*i + 1)%16;
		//Third round
		} else if (32<=i && i<=47) {
			return (3*i + 5)%16;
		//Fourth round
		} else {
			return (7*i)%16;
		}
	}
	
	private byte[] F(byte[] X, byte[] Y, byte[] Z, int k) {
		byte[] result = new byte[X.length];
		if(0<=k && k<=15) {
			for(int i=0;i<X.length;i++) {
				//F(X,Y,Z) = XY v not(X) Z
				result[i] = (byte) ((X[i] & Y[i]) | (~X[i] & Z[i]));
			}
		}
		if(16<=k && k<=31) {
			for(int i=0;i<X.length;i++) {
				//G(X,Y,Z) = XZ v Y not(Z)
				result[i] = (byte) ((X[i] & Z[i]) | (Y[i] & ~Z[i]));
			}
		}
		if(32<=k && k<=47) {
			for(int i=0;i<X.length;i++) {
				//H(X,Y,Z) = X xor Y xor Z
				result[i] = (byte) (X[i] ^ Y[i] ^ Z[i]);
			}
		}
		if(48<=k && k<=63) {
			for(int i=0;i<X.length;i++) {
				//I(X,Y,Z) = Y xor (X v not(Z))
				result[i] = (byte) (Y[i] ^ (X[i] | ~Z[i]));
			}
		}
		return result;
	}
	
	//The addition goes from 3 to 0 (BIG_ENDIAN mode)
	private byte[] add(byte[] A, byte[] B) {
		byte[] result = new byte[A.length];
		int carry = 0;
		for(int i=A.length - 1;i>=0;i--) {
			int sum = (A[i] & 0xFF) + (B[i] & 0xFF) + carry;
			result[i] = (byte) sum;
			carry = sum >> 8;
		}
		return result;
	}
	
	//return the value from table T
	private byte[] getTTableValue(int t) {
		return toByteArray(INT_T[t]);
	}
	
	private byte[] leftRotate(byte[] value, int rotate) {
		int intValue = toInt(value);
		int newValue = (intValue << rotate) | (intValue >>> (32 - rotate));
		return toByteArray(newValue);
	}
	
	//convert to byte[] considering BIG_ENDIAN
	private byte[] toByteArray(int value) {
		return new byte[] {
				(byte) ((value >> 24) & 0xFF),
				(byte) ((value >> 16) & 0xFF),
				(byte) ((value >> 8) & 0xFF),
				(byte) ((value >> 0) & 0xFF)
		};
	}
	
	//convert to int considering BIG_ENDIAN
	private int toInt(byte[] bytes) {
	     return ((bytes[0] & 0xFF) << 24) | 
	            ((bytes[1] & 0xFF) << 16) | 
	            ((bytes[2] & 0xFF) << 8 ) | 
	            ((bytes[3] & 0xFF) << 0 );
	}
	
}
