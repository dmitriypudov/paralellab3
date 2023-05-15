#include <iostream>
#include <mpi.h>
#include <sstream>
#include <iomanip>


class SHA256 {

public:
	SHA256();
	void update(uint8_t* data, size_t length); // обновить хэш-сумму с использованием массива входных данных длины length
	void update(std::string& s); // обновить хэш-сумму с использованием строки входных данных s
	uint8_t* digest(); // получить значение хэш-суммы
	std::string hash(std::string& data) // рассчитать хэш-сумму и вернуть ее в виде строки 
	{
		update(data);
		uint8_t* digest = this->digest();
		std::string result = SHA256::toString(digest);
		delete[] digest;

		return result;
	}

	static std::string toString(uint8_t* digest); // преобразовать хэш-сумму в строку

private:
	uint8_t  m_data[64]; // блок данных размером 64 байта
	uint32_t m_blocklen; // длина текущего блока данных (в битах)
	uint64_t m_bitlen; // общая длина данных (в битах)
	uint32_t m_state[8]; // вектор состояния хэш-функции (A, B, C, D, E, F, G, H)

	static uint32_t K[64]; // таблица констант K_i
	static uint32_t rotr(uint32_t x, uint32_t n); // циклический сдвиг вправо на n бит для числа x
	static uint32_t choose(uint32_t e, uint32_t f, uint32_t g); // функция выбора для реализации ф-ции F
	static uint32_t majority(uint32_t a, uint32_t b, uint32_t c); // функция большинства для реализации ф-ции G
	static uint32_t sig0(uint32_t x); // булева функция Sig0 для реализации ф-ций F и G
	static uint32_t sig1(uint32_t x); // булева функция Sig1 для реализации ф-ций F и G
	void transform(); // преобразовать текущий блок данных и обновить вектор состояния
	void pad(); // дополнить данные до размерности кратной 512 битам (согласно стандарту SHA-256)
	void revert(uint8_t* hash); // перевернуть байты хэш-суммы (так как алгоритм работает с big-endian)
};

uint32_t SHA256::K[64] = { // массив констант для использования в преобразовании блоков
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

SHA256::SHA256() : m_blocklen(0), m_bitlen(0) { 	// конструктор класса SHA256, задаем начальные значения вектора состояния
	m_state[0] = 0x6a09e667;
	m_state[1] = 0xbb67ae85;
	m_state[2] = 0x3c6ef372;
	m_state[3] = 0xa54ff53a;
	m_state[4] = 0x510e527f;
	m_state[5] = 0x9b05688c;
	m_state[6] = 0x1f83d9ab;
	m_state[7] = 0x5be0cd19;
}

void SHA256::update(uint8_t* data, size_t length) { // метод класса для обновления хэш-суммы с использованием массива данных
	for (size_t i = 0; i < length; i++) {
		m_data[m_blocklen++] = data[i];
		if (m_blocklen == 64) {
			transform();

			// End of the block
			m_bitlen += 512;
			m_blocklen = 0;
		}
	}
}

void SHA256::update(std::string& s) { // метод класса для обновления хэш-суммы с использованием строки данных
	std::string str = s;
	uint8_t* my_uint8_ptr = reinterpret_cast<uint8_t*>(const_cast<char*>(str.data()));
	update(my_uint8_ptr, s.size());
}

uint8_t* SHA256::digest() { // метод класса для получения значения хэш-суммы
	uint8_t* hash = new uint8_t[32];

	pad();
	revert(hash);

	return hash;
}

uint32_t SHA256::rotr(uint32_t x, uint32_t n) { // функция для циклического сдвига числа вправо на n бит
	return (x >> n) | (x << (32 - n));
}

uint32_t SHA256::choose(uint32_t e, uint32_t f, uint32_t g) { //  принимает три 32-битных числа: e, f и g, выполняет логическое "И" между e и f, затем выполняет отрицание e и выполняет логическое "И" между результатом и g
	return (e & f) ^ (~e & g);
}

uint32_t SHA256::majority(uint32_t a, uint32_t b, uint32_t c) { // принимает три 32-битных числа: a, b и c. Функция вычисляет логическое "И" между a и b, затем логическое "И" между a и c.
	return (a & (b | c)) | (b & c);
}

uint32_t SHA256::sig0(uint32_t x) { // Выполняет циклический сдвиг вправо на 7 бит, вправо на 18 бит, сдвиг вправо на 3 бита
	return SHA256::rotr(x, 7) ^ SHA256::rotr(x, 18) ^ (x >> 3);
}

uint32_t SHA256::sig1(uint32_t x) {
	return SHA256::rotr(x, 17) ^ SHA256::rotr(x, 19) ^ (x >> 10); // то же самое только циклич. на 17 19 и сдвиг 19
}

void SHA256::transform() {
	uint32_t maj, xorA, ch, xorE, sum, newA, newE, m[64];
	uint32_t state[8];

	for (uint8_t i = 0, j = 0; i < 16; i++, j += 4) { // Разделить данные на 32-битные блоки для 16 первых слов
		m[i] = (m_data[j] << 24) | (m_data[j + 1] << 16) | (m_data[j + 2] << 8) | (m_data[j + 3]);
	}

	for (uint8_t k = 16; k < 64; k++) { // Оставшиеся 48 блоков
		m[k] = SHA256::sig1(m[k - 2]) + m[k - 7] + SHA256::sig0(m[k - 15]) + m[k - 16];
	}

	for (uint8_t i = 0; i < 8; i++) {
		state[i] = m_state[i];
	}

	for (uint8_t i = 0; i < 64; i++) {
		maj = SHA256::majority(state[0], state[1], state[2]);
		xorA = SHA256::rotr(state[0], 2) ^ SHA256::rotr(state[0], 13) ^ SHA256::rotr(state[0], 22);

		ch = choose(state[4], state[5], state[6]);

		xorE = SHA256::rotr(state[4], 6) ^ SHA256::rotr(state[4], 11) ^ SHA256::rotr(state[4], 25);

		sum = m[i] + K[i] + state[7] + ch + xorE;
		newA = xorA + maj + sum;
		newE = state[3] + sum;

		state[7] = state[6];
		state[6] = state[5];
		state[5] = state[4];
		state[4] = newE;
		state[3] = state[2];
		state[2] = state[1];
		state[1] = state[0];
		state[0] = newA;
	}

	for (uint8_t i = 0; i < 8; i++) {
		m_state[i] += state[i];
	}
}

void SHA256::pad() {

	uint64_t i = m_blocklen;
	uint8_t end = m_blocklen < 56 ? 56 : 64;

	m_data[i++] = 0x80; // Добавить бит 1
	while (i < end) {
		m_data[i++] = 0x00; // Дополнение с нулями
	}

	if (m_blocklen >= 56) {
		transform();
		memset(m_data, 0, 56);
	}

	// Добавим к заполнению общую длину сообщения в битах и ​​преобразуем
	m_bitlen += m_blocklen * 8;
	m_data[63] = m_bitlen;
	m_data[62] = m_bitlen >> 8;
	m_data[61] = m_bitlen >> 16;
	m_data[60] = m_bitlen >> 24;
	m_data[59] = m_bitlen >> 32;
	m_data[58] = m_bitlen >> 40;
	m_data[57] = m_bitlen >> 48;
	m_data[56] = m_bitlen >> 56;
	transform();
}

void SHA256::revert(uint8_t* hash) {
	// SHA использует обратный порядок байтов
	// Вернуть все байты
	for (uint8_t i = 0; i < 4; i++) {
		for (uint8_t j = 0; j < 8; j++) {
			hash[i + (j * 4)] = (m_state[j] >> (24 - i * 8)) & 0x000000ff;
		}
	}
}

std::string SHA256::toString(uint8_t* digest) { // функция, которая преобразует массив байтов (хеш-сумму) в строку в шестнадцатеричном формате и возвращает эту строку
	std::stringstream s;
	s << std::setfill('0') << std::hex;

	for (uint8_t i = 0; i < 32; i++) {
		s << std::setw(2) << (unsigned int)digest[i];
	}

	return s.str();
}

const int K = 5; // константа, определяющая количество нулевых битов, которые должны быть в начале хеш-суммы для того, чтобы nonce считался допустимым.

bool IsValid(std::string hash) { // Хеш-сумма считается допустимой, если первые K символов равны '0'.
	for (int i = 0; i < K; i++) {
		if (hash.at(i) != '0') return false;
	}

	return true;
}

std::string toString(unsigned int v) { // функция, которая преобразует целое число в строку и возвращает эту строку.
	std::stringstream ss;
	ss << v;
	return ss.str();
}

void SendInputData(int rank, std::string& input) // функция, которая передает входные данные от процесса с рангом 0 всем другим процессам.
{
	int lineSize = input.size();
	MPI_Bcast(&lineSize, 1, MPI_INT, 0, MPI_COMM_WORLD);
	if (rank != 0)
		input.resize(lineSize);

	MPI_Bcast(const_cast<char*>(input.data()), lineSize, MPI_CHAR, 0, MPI_COMM_WORLD);
}

void GuessNonce(std::string resultString, std::string input, unsigned nonce, SHA256 sha) // функция, которая формирует строку из входных данных и nonce и проверяет, является ли полученная хеш-сумма допустимой. Если да, то nonce отправляется на процесс с рангом 0.
{
	resultString = input + toString(nonce);
	if (IsValid(sha.hash(resultString)))
		MPI_Send(&nonce, 1, MPI_UNSIGNED, 0, 0, MPI_COMM_WORLD);
}

int main(int argc, char** argv)
{
	MPI_Init(&argc, &argv);

	int size, rank;
	MPI_Status status;
	MPI_Request request;
	MPI_Comm_size(MPI_COMM_WORLD, &size);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	SHA256 sha;


	std::string resultString, input;
	if (rank == 0)
	{
		std::cout << "Diff  " << K << std::endl;
		std::cout << "Enter ";
		std::cin >> input;
	}

	SendInputData(rank, input); // передача входных данных от процесса с рангом 0 всем другим процессам.

	MPI_Irecv(0, 0, MPI_INT, 0, 0, MPI_COMM_WORLD, &request); // асинхронный прием сообщения от процесса с рангом 0.

	unsigned int nonce = INT_MAX / (rank + 1); //  начальное значение nonce, которое зависит от ранга процесса.
	double startTime = MPI_Wtime();
	while (rank != 0)
	{
		int flag = 0;
		MPI_Test(&request, &flag, &status);
		if (flag)
			break;

		GuessNonce(resultString, input, nonce, sha); //  формирование строки и проверка полученной хеш-суммы на допустимость.

		++nonce;
	}

	if (rank == 0)
	{
		bool found = false; // флаг, который показывает, был ли найден допустимый nonce.
		while (!found) // цикл, который работает до тех пор, пока не будет найден допустимый nonce.
		{
			MPI_Recv(&nonce, 1, MPI_UNSIGNED, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &status); // прием сообщения от любого процесса, принимается значение nonce, которое было отправлено на процесс с рангом 0.
			std::string resultString = input + toString(nonce);
			std::string hash = sha.hash(resultString); // вычисление хеш-суммы для формированной строки.
			found = IsValid(hash);

			if (found)
			{
				std::cout << "Time -  " << MPI_Wtime() - startTime << "s" << std::endl; // вывод времени
				for (int i = 1; i < size; ++i)
					MPI_Send(0, 0, MPI_INT, i, 0, MPI_COMM_WORLD);

				std::cout << "Hash(" << input << " + " << nonce << ") = " << hash << std::endl;
			}
		}
	}

	MPI_Finalize();
}
