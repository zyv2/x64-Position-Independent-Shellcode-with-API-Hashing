#include <iostream>
#include <fstream>

// based on xxhash but for one bit (can be optimized)
int hash(const char* function_name) {
	unsigned int hash = 0;
	unsigned char ch = 0;
	unsigned char rotated_ch = 0;
	for (; *function_name; function_name++) {
		ch = (unsigned char)*function_name;
		// 5 is coprime to 8
		rotated_ch = ((ch << 5) | (ch >> (8 - 5)));

		hash = (hash * 30) + rotated_ch;
	}
	return hash;
}


void enumExports(const char *path, int (*callback)(const char *)) {

	unsigned int e_lfanew = 0;
	unsigned int export_table = 0;
	unsigned int functions_count = 0;
	unsigned int function_names_offset = 0;
	unsigned int function_names_array = 0;
	std::string buff;
	std::FILE *f = std::fopen(path, "r");

	if (fgetc(f) == 'M' && fgetc(f) == 'Z') {
		
		fseek(f, 0x3c, SEEK_SET);
		fread(&e_lfanew, sizeof(int), 1, f);
		printf("e_lfanew : %d\n", e_lfanew);

		fseek(f, e_lfanew + 0x88, SEEK_SET);
		fread(&export_table, sizeof(int), 1, f);
		printf("export_table : %x\n", export_table);

		fseek(f, export_table + 0x14, SEEK_SET);
		fread(&functions_count, sizeof(int), 1, f);
		printf("functions count : %d\n", functions_count);

		fseek(f, export_table + 0x20, SEEK_SET);
		fread(&function_names_offset, sizeof(int), 1, f);
		printf("functions names offset: %x\n", function_names_offset);
		
		char line[255];
		unsigned int ch = 0;
		unsigned int curr_function_name_offset = 0;
		std::ofstream outputFile("Functions_dump.txt");
		fseek(f, function_names_offset, SEEK_SET);
		for (int i = 1; i <= functions_count; i++) {
			fread(&function_names_array, sizeof(int), 1, f);
			printf("function[%d] offset: %.04x\n", i, function_names_array);
			
			fseek(f, function_names_array, SEEK_SET);
			while ((ch = fgetc(f)) != EOF && ch != '\0') {
				buff.push_back((char)ch);
			}
			sprintf(&line[0], "[%d] %s -> 0x%.04x\n", i, buff.c_str(), callback(buff.c_str()));
			outputFile << line;
			buff.clear();
			curr_function_name_offset = function_names_offset + (sizeof(int) * i);
			fseek(f, curr_function_name_offset, SEEK_SET);
		}
		outputFile.close();
	}
	return;
}


int main() {
	enumExports("C:\\Windows\\System32\\kernel32.dll", hash);
	return 0;
}