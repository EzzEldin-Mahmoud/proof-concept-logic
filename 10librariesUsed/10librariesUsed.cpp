#define _CRT_SECURE_NO_WARNINGS
#include <cstdio>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <expat.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <zip.h>
#include <boost/filesystem.hpp>
#include <boost/system/error_code.hpp>
#include <boost/regex.hpp>
#include <boost/thread.hpp>
#include <absl/strings/str_cat.h>
#include <absl/strings/str_split.h>
#include <absl/time/clock.h>
#include <absl/time/time.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <aubio/aubio.h>

// Function to list files in a directory using Boost
void listFiles(const std::string& path) {
    boost::filesystem::path dir(path);
    if (boost::filesystem::exists(dir) && boost::filesystem::is_directory(dir)) {
        for (const auto& entry : boost::filesystem::directory_iterator(dir)) {
            std::cout << entry.path().string() << std::endl;
        }
    }
    else {
        std::cerr << "Directory does not exist: " << path << std::endl;
    }
}

// Function to read a file using Boost
void readFile(const std::string& filename) {
    std::ifstream file(filename);
    if (file) {
        std::cout << "Reading file: " << filename << std::endl;
        std::cout << file.rdbuf(); // Output file content
    }
    else {
        std::cerr << "Error opening file: " << filename << std::endl;
    }
}

// Function to use regex to search for a pattern in a string
void regexExample(const std::string& text, const std::string& pattern) {
    boost::regex regexPattern(pattern);
    if (boost::regex_search(text, regexPattern)) {
        std::cout << "Pattern found: " << pattern << std::endl;
    }
    else {
        std::cout << "Pattern not found: " << pattern << std::endl;
    }
}

// Function to demonstrate multi-threading with Boost
void threadFunction(int id) {
    std::cout << "Thread " << id << " is running." << std::endl;
    boost::this_thread::sleep_for(boost::chrono::seconds(1)); // Simulate work
    std::cout << "Thread " << id << " has finished." << std::endl;
}

// Callback functions for Expat
void XMLCALL startElement(void* userData, const char* name, const char** atts) {
    std::cout << "Start Element: " << name << std::endl;
}

void XMLCALL endElement(void* userData, const char* name) {
    std::cout << "End Element: " << name << std::endl;
}

void runAnsiblePlaybook(const char* playbook) {
    std::string command = "ansible-playbook ";
    command += playbook;

    int result = system(command.c_str());
    if (result != 0) {
        std::cerr << "Failed to execute Ansible playbook: " << playbook << std::endl;
    }
    else {
        std::cout << "Ansible playbook executed successfully: " << playbook << std::endl;
    }
}

// Example usage of libxml2
void parseXML(const char* filename) {
    xmlDocPtr doc = xmlReadFile(filename, NULL, 0);
    if (doc == NULL) {
        std::cerr << "Could not parse XML file: " << filename << std::endl;
        return;
    }

    xmlNodePtr root = xmlDocGetRootElement(doc);
    std::cout << "Root Element: " << root->name << std::endl;

    // Traversing the XML tree
    for (xmlNodePtr node = root->children; node; node = node->next) {
        if (node->type == XML_ELEMENT_NODE) {
            std::cout << "Element Name: " << node->name << std::endl;
        }
    }

    xmlFreeDoc(doc);
    xmlCleanupParser();
}

// Example usage of libzip
void createZip(const char* zipname) {
    int error = 0;
    zip_t* zip = zip_open(zipname, ZIP_CREATE | ZIP_TRUNCATE, &error);

    if (zip == NULL) {
        std::cerr << "Could not create zip archive: " << zipname << std::endl;
        return;
    }

    const char* filename = "test.txt";
    const char* data = "This is a test file.";

    zip_source_t* source = zip_source_buffer(zip, data, strlen(data), 0);
    if (source == NULL || zip_file_add(zip, filename, source, ZIP_FL_OVERWRITE) < 0) {
        zip_source_free(source);
        std::cerr << "Could not add file to zip archive." << std::endl;
        zip_close(zip);
        return;
    }

    zip_close(zip);
    std::cout << "Zip archive created: " << zipname << std::endl;
}

void generateRSAKey() {
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (!ctx) {
        std::cerr << "Error creating context: " << ERR_get_error() << std::endl;
        return;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Error initializing keygen: " << ERR_get_error() << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "Error setting keygen bits: " << ERR_get_error() << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "Error generating RSA key: " << ERR_get_error() << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return;
    }

    // Save the private key
    FILE* key_file = fopen("private_key.pem", "wb");
    if (key_file) {
        PEM_write_PrivateKey(key_file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(key_file);
    }
    else {
        std::cerr << "Error opening key file." << std::endl;
    }

    // Clean up
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

// Example usage of Abseil
void abseilExample() {
    // Concatenating strings using Abseil
    std::string hello = "Hello";
    std::string world = "World";
    std::string message = absl::StrCat(hello, ", ", world, "!");
    std::cout << message << std::endl;

    // Splitting a string using Abseil
    std::string str = "one,two,three";
    std::vector<std::string> parts = absl::StrSplit(str, ',');
    std::cout << "Splitted string parts:" << std::endl;
    for (const auto& part : parts) {
        std::cout << part << std::endl;
    }

    // Using Abseil's time utilities
    absl::Time now = absl::Now();
    std::cout << "Current time: " << absl::FormatTime(now) << std::endl;
}
void detectBeats(const char* filename) {
    aubio_source_t* source = new_aubio_source(filename, 0, 512);
    if (!source) {
        std::cerr << "Error opening audio file: " << filename << std::endl;
        return;
    }

    aubio_tempo_t* tempo = new_aubio_tempo("default", 512, 256, 44100);
    fvec_t* in = new_fvec(512);
    fvec_t* out = new_fvec(2);
    uint_t read = 0;

    while (read > 0) {
        aubio_source_do(source, in, &read);
        aubio_tempo_do(tempo, in, out);
        if (out->data[0] != 0) {
            std::cout << "Beat detected at time: " << aubio_tempo_get_last_s(tempo) << " seconds" << std::endl;
        }
    }

    del_aubio_tempo(tempo);
    del_aubio_source(source);
    del_fvec(in);
    del_fvec(out);
}

int main() {
    // Example directory to list files
    listFiles("./"); // Replace with your directory path

    // Example file reading
    readFile("example.txt"); // Replace with your file path

    // Example regex search
    regexExample("Boost is a set of C++ libraries.", "Boost");

    // Example threading
    const int threadCount = 3;
    boost::thread_group threads;
    for (int i = 0; i < threadCount; ++i) {
        threads.create_thread(boost::bind(threadFunction, i));
    }
    threads.join_all(); // Wait for all threads to finish

    // **libjansson usage**
    json_t* json = json_object();
    json_object_set_new(json, "key", json_string("value"));
    char* json_str = json_dumps(json, JSON_INDENT(4));
    std::cout << "Generated JSON:\n" << json_str << std::endl;
    json_decref(json);
    free(json_str);

    // **OpenSSL usage**
    generateRSAKey();

    // **libexpat usage**
    const char* xml = "<root><element key='value'>Text</element></root>";
    XML_Parser parser = XML_ParserCreate(NULL);
    XML_SetElementHandler(parser, startElement, endElement);
    if (XML_Parse(parser, xml, std::strlen(xml), XML_TRUE) == XML_STATUS_ERROR) {
        std::cerr << "Expat parsing error: " << XML_ErrorString(XML_GetErrorCode(parser)) << std::endl;
    }
    XML_ParserFree(parser);

    // **libxml2 usage**
    parseXML("example.xml");

    // **libzip usage**
    createZip("example.zip");

    // **Ansible usage**
    runAnsiblePlaybook("example_play");

    // Example beat detection with aubio
    detectBeats("audio_file.wav");
    return 0;
}
