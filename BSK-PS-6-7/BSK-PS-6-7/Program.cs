using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BSK_PS_6_7
{
    class KeyGenerator
    {
        public List<int[]> keyList { get; set; } // 16 x 48bits

        private int[] PC1;
        private int[] PC2;


        public KeyGenerator(string keyFileName)
        {
            prepareTables();
            setKey(keyFileName);
        }

       

        private void generateKeys(int[] key64)
        {
            keyList = new List<int[]>();
            int i, j;
            int[] C = new int[28];
            int[] D = new int[28];
            int[] key56;
            int[] key48;

            key56 = pc1(key64); // transform pc1: 64-8=56bits

            for(i = 0; i < 28; i++)
            {
                C[i] = key56[i];
                D[i] = key56[i + 28];
            }

            for(i=0; i<16; i++)
            {
                shift(ref C, ref D, (i == 0 || i == 1 || i == 8 || i == 15) ? 1 : 2);

                key56 = merge(ref C, ref D);

                key48 = pc2(key56);

                keyList.Add(key48);
            }
        }

        private int[] pc1(int[] key64)
        {
            int[] newKey56 = new int[56];

            for (int i = 0; i < 56; i++)
            {
                newKey56[i] = key64[PC1[i]];
            }

            return newKey56;
        }

        private int[] pc2(int[] key56) // transform PC2
        {
            int[] newKey48 = new int[48];

            for(int i=0; i<48; i++)
            {
                newKey48[i] = key56[PC2[i]];
            }

            return newKey48;
        }

        private int[] merge(ref int[] C, ref int[] D) // merge C and D
        {
            int[] key56 = new int[56];
            for (int i = 0; i < 28; i++)
            {
                key56[i] = C[i];
                key56[i + 28] = D[i];
            }
            return key56;
        }

        private void shift(ref int[] C, ref int[] D, int number)
        {
            int Ctmp = C[0], Dtmp = D[0], i;

            for(i=0; i<27; i++)
            {
                C[i] = C[i + 1];
                D[i] = D[i + 1];
            }

            C[27] = Ctmp;
            D[27] = Dtmp;

            if(number==2)
            {
                Ctmp = C[0];
                Dtmp = D[0];

                for (i = 0; i < 27; i++)
                {
                    C[i] = C[i + 1];
                    D[i] = D[i + 1];
                }

                C[27] = Ctmp;
                D[27] = Dtmp;
            }

        }

        private void prepareTables() // load PC1, PC2 from file
        {
            int i, j, index, ii;
            string[] fileLines;
            string[] line;

            PC1 = new int[56];
            PC2 = new int[48];

            fileLines = System.IO.File.ReadAllLines(Directory.GetCurrentDirectory() + @"\tables\PC1.txt");
            for (i = 0, index = 0; i <9; i++)
            {
                if (i == 4) { continue; }
                line = fileLines[i].Split();
                for (j = 0; j < 7; j++)
                {
                    PC1[index++] = Int32.Parse(line[j]) - 1;
                }
            }

            fileLines = System.IO.File.ReadAllLines(Directory.GetCurrentDirectory() + @"\tables\PC2.txt");
            for (i = 0, index = 0; i < 8; i++)
            {
                line = fileLines[i].Split();
                for (j = 0; j < 6; j++)
                {
                    PC2[index++] = Int32.Parse(line[j]) - 1;
                }
            }
        }

        private int[] readKeyFromFile(string keyFileName) // return 64bits key
        {
            int[] key64;
            int i;
            string line = File.ReadAllText(Directory.GetCurrentDirectory() + @"\tables\" + keyFileName).Replace(" ", "");

            key64 = new int[line.Length];
            for (i = 0; i < 64; i++)
            {
                key64[i] = Int32.Parse(line[i].ToString());
            }

            return key64;

        }

        public void setKey(string keyFileName)
        {
            generateKeys(readKeyFromFile(keyFileName));
        }
    }
    class DES
    {
        public byte[] plainFileBytes { get; set; }      // table of input bytes
        public byte[] encodedFileBytes { get; set; }    // table of final bytes, ready to write to OUT file
        public KeyGenerator keyGenerator { get; set; }  // this object generate 16 keys. Every has a 48 bits
        public int[] IP { get; set; }                   // initial permutation
        public int[] IPReverse { get; set; }            // inverse of initial permutation
        public int[] E { get; set; }                    // table E
        public int[] P { get; set; }                    // table P
        public int[,,]S { get; set; }                   // table of all 8 S tables(S0-S7). [8, 4, 16]

        public string plainFileName { get; set; }       // name of input file
        public string keyFileName { get; set; }         // name of key file


        public DES(string plainFileName, string keyFileName)
        {
            this.plainFileName = plainFileName;
            this.keyFileName   = keyFileName;

            setPlainText(plainFileName, 'e');

            prepareTables();

            keyGenerator = new KeyGenerator(keyFileName);
        }


        internal void encode()
        {
            setPlainText(plainFileName, 'e');

            BinaryWriter br;
            int i, j, numberOf64Inputs;
            int[] plain64;
            int[] L = new int[32];
            int[] R = new int[32];
            int[] f = new int[32];
            int[] xor = new int[32];
            int[] Rcopy = new int[32]; // bufor
            int indexOfResult=0;

            encodedFileBytes = new byte[plainFileBytes.Length];
            numberOf64Inputs = plainFileBytes.Length / 8;

            for(i=0; i<numberOf64Inputs; i++)
            {
                plain64 = next64Inputs(i);

                plain64 = ip(plain64); // initial permutation

                for(j=0; j<32; j++)
                {
                    L[j] = plain64[j];
                    R[j] = plain64[j + 32];
                }

                for(j=0; j<16; j++)
                {
                    f = generateF(keyGenerator.keyList[j], R);
                    Rcopy = makeCopy(R);

                    R = makeXor(L, f);
                    L = makeCopy(Rcopy);
                }


                for (j = 0; j < 32; j++)
                {
                    plain64[j] = R[j];
                    plain64[j + 32] = L[j];
                }

                plain64 = ipReverse(plain64);

                addToEncoded(plain64, ref indexOfResult);
            }


            br = new BinaryWriter(new FileStream(System.IO.Directory.GetCurrentDirectory() + @"\" + plainFileName.Substring(0, plainFileName.IndexOf('.')) + "OUT.bin", FileMode.Create));
            br.Write(encodedFileBytes);
            br.Close();
        }

        private void addToEncoded(int[] plain64, ref int indexOfResult)
        {
            int i, j;
            string s = "";
            for (i=0; i<8; i++)
            {
                s = "";
                for (j = 0; j < 8; j++)
                    s += plain64[j + 8*i];
                encodedFileBytes[indexOfResult++] = Convert.ToByte(s, 2);
            }
        }

        private int[] ipReverse(int[] plain64)
        {
            int[] newPlain64 = new int[64];
            int i;

            for (i = 0; i < 64; i++)
            {
                newPlain64[i] = plain64[IPReverse[i]];
            }

            return newPlain64;
        }

        private int[] makeCopy(int[] r)
        {
            int[] copy = new int[r.Length];
            int i;

            for(i=0; i<r.Length; i++)
            {
                copy[i] = r[i];
            }

            return copy;
        }

        private int[] generateF(int[] key, int[] r32)
        {
            int[] r48;
            int[] xor48;
            int[] result32 = new int[32];
            int i, j, newNumber, resultIndex;
            string columnIndex, rowIndex, newS;

            r48 = e(r32);
            xor48 = makeXor(r48, key);

            for(i=0, resultIndex=0; i<8; i++) //for every S
            {
                rowIndex = xor48[0 + i * 6].ToString() + xor48[5 + i * 6].ToString();
                columnIndex = xor48[1 + i * 6].ToString() + xor48[2 + i * 6].ToString() + xor48[3 + i * 6].ToString() + xor48[4 + i * 6];
                newNumber = S[i, Convert.ToInt32(rowIndex, 2), Convert.ToInt32(columnIndex, 2)];
                newS = Convert.ToString(newNumber, 2).PadLeft(4, '0');

                for(j=0; j<4; j++)
                {
                    result32[resultIndex++] = Convert.ToInt32(newS[j])-48;
                }
            }

            result32 = p(result32);

            return result32;
        }

        private int[] p(int[] result32)
        {
            int[] r32 = new int[32];

            for (int i = 0; i < 32; i++)
            {
                r32[i] = result32[P[i]];
            }

            return r32;
        }

        private int[] makeXor(int[] a, int[] b)
        {
            int i, size;
            size = a.Length;
            int[] result = new int[size];

            for(i=0; i<size; i++)
            {
                result[i] = a[i] ^ b[i];
            }

            return result;
        }

        private int[] e(int[] r32)
        {
            int[] r48 = new int[48];

            for(int i=0; i<48; i++)
            {
                r48[i] = r32[E[i]];
            }

            return r48;
        }

        private int[] ip(int[] plain64)
        {
            int[] newPlain64 = new int[64];
            int i;

            for(i=0; i<64; i++)
            {
                newPlain64[i] = plain64[IP[i]];
            }

            return newPlain64;
        }

        private int[] next64Inputs(int iteration)
        {
            int[] plain64 = new int[64];
            int i, j, index;
            string byteTmp="";

            for(i=0, index=0; i<8; i++) // for 8 bytes, 8x8=64
            {
                byteTmp = Convert.ToString(plainFileBytes[i+iteration*8], 2).PadLeft(8, '0'); // we have string of 8 digits representing one byte. Example 00001100
                for(j=0; j<8; j++) // for 8 bites of 1 bite
                {
                    plain64[index++] = Int32.Parse(byteTmp[j].ToString());
                }
            }

            return plain64;
        }

        private void prepareTables() // load IP, IPReverse, E, P, S1-8, ...
        {
            int i,j, index, ii;
            string[] fileLines;
            string[] line;

            IP = new int[64];
            IPReverse = new int[64];
            E = new int[48];
            P = new int[32];
            S = new int[8, 4, 16];

            fileLines = System.IO.File.ReadAllLines(Directory.GetCurrentDirectory() + @"\tables\IP.txt");
            for (i=0, index=0; i<8; i++)
            {
                line = fileLines[i].Split();
                for(j=0; j<8; j++)
                {
                    IP[index++] = Int32.Parse(line[j])-1;
                }
            }

            fileLines = System.IO.File.ReadAllLines(Directory.GetCurrentDirectory() + @"\tables\IPReverse.txt");
            for (i = 0, index = 0; i < 8; i++)
            {
                line = fileLines[i].Split();
                for (j = 0; j < 8; j++)
                {
                    IPReverse[index++] = Int32.Parse(line[j])-1;
                }
            }

            fileLines = System.IO.File.ReadAllLines(Directory.GetCurrentDirectory() + @"\tables\E.txt");
            for (i = 0, index = 0; i < 8; i++)
            {
                line = fileLines[i].Split();
                for (j = 0; j < 6; j++)
                {
                    E[index++] = Int32.Parse(line[j]) - 1;
                }
            }

            fileLines = System.IO.File.ReadAllLines(Directory.GetCurrentDirectory() + @"\tables\P.txt");
            for (i = 0, index = 0; i < 8; i++)
            {
                line = fileLines[i].Split();
                for (j = 0; j < 4; j++)
                {
                    P[index++] = Int32.Parse(line[j]) - 1;
                }
            }

            fileLines = System.IO.File.ReadAllLines(Directory.GetCurrentDirectory() + @"\tables\S.txt");
            for (ii=0; ii<8; ii++) // for every S: 1..6
            {
                for (i = 0, index = 0; i < 4; i++)
                {
                    line = fileLines[i + ii*5].Split();
                    for (j = 0; j < 16; j++)
                    {
                        S[ii,i,j] = Int32.Parse(line[j]);
                    }
                }
            }
        }

        public void setPlainText(string plainFileName, char mode) // always we have multiple of 64
        {
            int amount, newAmount, i;
            byte[] newPlainFileBytes;
            Random random = new Random();

            plainFileBytes = File.ReadAllBytes(System.IO.Directory.GetCurrentDirectory() + @"\" + plainFileName);

            if(mode == 'e') // PADDING: when we decode we always have multiple of 64 bits. Only when we encode we have to modify input Bytes
            {
                amount = plainFileBytes.Length;

                // if not multiple of 64, example: ....11001100 1101____ -> we have to: add cells to achieve multiple of 64 bits file,
                //                                                                      generate random bits in these cells,
                //                                                                      in the last cell we write how many bits we added
                if (amount % 8 != 0) 
                {
                    newAmount = amount + (8 - amount % 8);

                    newPlainFileBytes = new byte[newAmount]; 

                    for (i = 0; i < amount; i++) // rewriting bits
                    {
                        newPlainFileBytes[i] = plainFileBytes[i];
                    }
                    for (i = amount; i < newAmount - 1; i++) // generate random bits in added cells
                    {
                        newPlainFileBytes[i] = Convert.ToByte(random.Next(0, 1));
                    }

                    // in the last added cell we write how many bits we added - how many bits we have to remove when we will be decoding file
                    newPlainFileBytes[newAmount - 1] = Convert.ToByte(newAmount - amount); 

                    plainFileBytes = newPlainFileBytes;
                }

                // if multiple of 64, example: ....11001100 11010011 -> we have to: add  64 cells(8 Byte),
                //                                                      generate random bits in these cells and in the last cell write how many bits we added
                else
                {
                    newAmount = amount + 8;
                    newPlainFileBytes = new byte[newAmount];

                    for (i = 0; i < amount; i++)
                    {
                        newPlainFileBytes[i] = plainFileBytes[i];
                    }
                    for (i = amount; i < newAmount - 1; i++)
                    {
                        newPlainFileBytes[i] = Convert.ToByte(random.Next(0, 1));
                    }

                    newPlainFileBytes[newAmount - 1] = Convert.ToByte(newAmount - amount);

                    plainFileBytes = newPlainFileBytes;
                }
            }
        }

        public void setKey(string keyFileName)
        {
            keyGenerator.setKey(keyFileName);
        }

        internal void decode()
        {
            setPlainText(plainFileName.Substring(0, plainFileName.IndexOf('.')) + "OUT.bin", 'd');


            BinaryWriter br;
            int i, j, numberOf64Inputs;
            int[] plain64;
            int[] L = new int[32];
            int[] R = new int[32];
            int[] f = new int[32];
            int[] xor = new int[32];
            int[] Rcopy = new int[32]; // bufor
            int indexOfResult = 0;

            encodedFileBytes = new byte[plainFileBytes.Length];
            numberOf64Inputs = plainFileBytes.Length / 8;

            for (i = 0; i < numberOf64Inputs; i++)
            {
                plain64 = next64Inputs(i);

                plain64 = ip(plain64);

                for (j = 0; j < 32; j++)
                {
                    L[j] = plain64[j];
                    R[j] = plain64[j + 32];
                }

                for (j = 0; j < 16; j++) // here is difference between encode and decode. We take keys in reverse order from k15 to K0.
                {
                    f = generateF(keyGenerator.keyList[15-j], R);
                    Rcopy = makeCopy(R);

                    R = makeXor(L, f);
                    L = makeCopy(Rcopy);
                }


                for (j = 0; j < 32; j++)
                {
                    plain64[j] = R[j];
                    plain64[j + 32] = L[j];
                }

                plain64 = ipReverse(plain64);

                addToEncoded(plain64, ref indexOfResult);
            }

            // we have to remove bites which where added for PADDING when we encode file
            int howManyDelete = Convert.ToInt32(encodedFileBytes[encodedFileBytes.Length-1]);
            byte[] newEncodedFileBytes = new byte[encodedFileBytes.Length-howManyDelete];
            for(i=0; i<newEncodedFileBytes.Length; i++)
            {
                newEncodedFileBytes[i] = encodedFileBytes[i];
            }
            encodedFileBytes = newEncodedFileBytes;

            br = new BinaryWriter(new FileStream(System.IO.Directory.GetCurrentDirectory() + @"\" + plainFileName.Substring(0, plainFileName.IndexOf('.')) + "OUT.bin", FileMode.Create));
            br.Write(encodedFileBytes);
            br.Close();
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            string plainFileName = "test2.bin"; // test2.bin is not a multiple of 64 bits
            string keyFileName = "key.txt";

            DES des = new DES(plainFileName, keyFileName);

            bool b = true;

            while (b)
            {
                Console.WriteLine("\n****************************************************************************************************************\n"
                                 + "file:        " + plainFileName + "\n"
                                 + "Choose action: change file(cf)  | encode(e) | decode(d) | q");
                switch (Console.ReadLine())
                {
                    case "cf":
                        setFile(ref plainFileName, des);
                        break;

                    case "e":
                        des.encode();
                        break;

                    case "d":
                        des.decode();
                        break;

                    case "q":
                        b = false;
                        break;
                }
            }

            Console.ReadKey();
        }


        private static void setFile(ref string fileName, DES des)
        {
            Console.WriteLine("Podaj nazwę pliku(z rozszerzeniem): ");
            fileName = Console.ReadLine();
            des.setPlainText(fileName, 'e'); // 'e' means encoding
            des.plainFileName = fileName;
        }
    }
}
