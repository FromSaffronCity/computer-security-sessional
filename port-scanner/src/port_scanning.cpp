#include<iostream>
#include<cstdlib>
#include<iomanip>
#include<string>
#include<sstream>
#include<vector>
#include<climits>

using namespace std;

#include<SFML/Network.hpp>

using namespace sf;

/*
	port scanning function definition:
		1) bool isPortOpen(): checks if target port on remote machine with provided ip address is open
*/

bool isPortOpen(const string& ipAddress, int port) {
	return (TcpSocket().connect(ipAddress, port) == Socket::Done);
}

/* 
	helping functions definition:
		1) vector<string> tokenize(): tokenizes input string with respect to provided delimiter (default, whitespace)
		2) int convertFromStringToInteger(): converts input string to integer
		3) vector<int> generateRange(): generates the range [minInteger, maxInteger]
		4) vector<int> parsePorts(): parses input string to extract target ports
		5) int findMax(): finds max value from a list of integers
		6) size_t countDigits(): counts number of digits of provided integer
*/

vector<string> tokenize(const string& str, char delimiter = ' ') {
	string token;
	stringstream sstream(str);
	vector<string> tokens;

	while(getline(sstream, token, delimiter)) {
		if(token.size() > 0) {
			tokens.push_back(token);
		}
	}
	return tokens;
}

int convertFromStringToInteger(const string& str) {
	stringstream sstream(str);
	int integer;

	sstream >> integer;
	return integer;
}

vector<int> generateRange(int minInteger, int maxInteger) {
	if(minInteger > maxInteger) {
		int temp = minInteger;
		minInteger = maxInteger;
		maxInteger = temp;
	}

	vector<int> range;

	for(int i=minInteger; i<=maxInteger; i++) {
		range.push_back(i);
	}
	return range;
}

vector<int> parsePorts(const string& str) {
	vector<int> ports;

	for(const string& token: tokenize(str, ',')) {
		vector<string> tokens = tokenize(token, '-');

		switch(tokens.size()) {
			case 1: {
				ports.push_back(convertFromStringToInteger(tokens[0]));
				break;
			}
			case 2: {
				for(int port: generateRange(convertFromStringToInteger(tokens[0]), convertFromStringToInteger(tokens[1]))) {
					ports.push_back(port);
				}
				break;
			}
			default: {
				break;
			}
		}
	}
	return ports;
}

int findMax(const vector<int>& integers) {
	int maxInteger = INT_MIN;

	for(int i=0; i<integers.size(); i++) {
		maxInteger = (integers[i] > maxInteger)? integers[i]: maxInteger;
	}
	return maxInteger;
}

size_t countDigits(int integer) {
	size_t digitCounter = (integer < 0)? 1: 0;
	integer = (integer < 0)? integer*(-1): integer;

	while(integer > 0) {
		integer /= 10;
		digitCounter++;
	}
	return digitCounter;
}

/*
	main function definition
*/

int main(int argc, char** argv) {
	string ipAddress;
	vector<int> ports;

	/* taking user inputs */
	if(argc == 1) {
		/* inputs from interactive invocation */
		cout << '\n' << "Target IP Address: " << flush;
		getline(cin, ipAddress);

		string str;

		cout << "Target Ports: " << flush;
		getline(cin, str);

		ports = parsePorts(str);
	} else if(argc == 3) {
		/* inputs from command line arguments */
		ipAddress = string(argv[1]);
		ports = parsePorts(string(argv[2]));
	} else {
		cerr << '\n' << "Usage: " << string(argv[0]) << " ipAddress ports" << '\n'
			 << '\n' << "Examples:" << '\n'
			 << '\t' << string(argv[0]) << " localhost 80" << '\n'
			 << '\t' << string(argv[0]) << " 127.0.0.1 80,443" << '\n'
			 << '\t' << string(argv[0]) << " scanme.nmap.org 21-25" << '\n'
			 << '\t' << string(argv[0]) << " 45.33.32.156 21-25,80,443" << '\n' << endl;
		exit(EXIT_FAILURE);
	}

	/* port scanning */
	size_t width = countDigits(findMax(ports));
	int openPortCounter = 0;

	cout << '\n' << string(argv[0]) << ": Port Scanning (" << ipAddress << ")..." << '\n' << endl;

	for(int i=0; i<ports.size(); i++) {
		if(isPortOpen(ipAddress, ports[i])) {
			cout << "Port " << setw(width) << ports[i] << ": OPEN" << endl;
			openPortCounter++;
		}
	}

	/* reference: https://stackoverflow.com/questions/18410234/how-does-one-represent-the-empty-char/18410297 */
	cout << ((openPortCounter > 0)? '\n': '\0') << string(argv[0]) << ": Port Scanning Completed, " << openPortCounter << '/' << ports.size() << " ports OPEN." << '\n' << endl;

	/*
		os fingerprinting:
			Run the python script os_fingerprinting.py for the time being.
	*/

	/* reference: https://www.geeksforgeeks.org/system-call-in-c/ */
	system(("sudo python os_fingerprinting.py "+ipAddress).c_str());

	return 0;
}

/*
	reference: Simple Port Scanner with C++ (http://www.cplusplus.com/articles/o2N36Up4/)
*/
