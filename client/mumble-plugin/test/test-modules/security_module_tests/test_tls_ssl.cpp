#include "test_security_module_main.cpp"

// 9.1 TLS/SSL Tests
TEST_F(TLSSSLTest, CertificateValidation) {
    // Test certificate validation
    EXPECT_FALSE(mock_tls_security->isSSLInitialized()) << "SSL should not be initialized initially";
    
    // Test SSL initialization
    bool init_result = mock_tls_security->initializeSSL();
    EXPECT_TRUE(init_result) << "SSL initialization should succeed";
    EXPECT_TRUE(mock_tls_security->isSSLInitialized()) << "SSL should be initialized";
    
    // Test certificate validation
    std::string cert_data = generateTestCertificate();
    bool cert_result = mock_tls_security->validateCertificate(cert_data);
    EXPECT_TRUE(cert_result) << "Certificate validation should succeed";
    EXPECT_TRUE(mock_tls_security->isCertificateValid()) << "Certificate should be valid";
    
    // Test invalid certificate
    std::string invalid_cert = "invalid_certificate_data";
    bool invalid_cert_result = mock_tls_security->validateCertificate(invalid_cert);
    EXPECT_FALSE(invalid_cert_result) << "Invalid certificate should be rejected";
    
    // Test empty certificate
    std::string empty_cert = "";
    bool empty_cert_result = mock_tls_security->validateCertificate(empty_cert);
    EXPECT_FALSE(empty_cert_result) << "Empty certificate should be rejected";
    
    // Test SSL cleanup
    mock_tls_security->cleanupSSL();
    EXPECT_FALSE(mock_tls_security->isSSLInitialized()) << "SSL should not be initialized after cleanup";
}

TEST_F(TLSSSLTest, StrongCipherSelection) {
    // Test strong cipher selection
    bool init_result = mock_tls_security->initializeSSL();
    EXPECT_TRUE(init_result) << "SSL initialization should succeed";
    
    // Test strong cipher selection
    bool cipher_result = mock_tls_security->selectStrongCipher();
    EXPECT_TRUE(cipher_result) << "Strong cipher selection should succeed";
    
    // Test cipher selection without SSL initialization
    mock_tls_security->cleanupSSL();
    bool cipher_result_no_ssl = mock_tls_security->selectStrongCipher();
    EXPECT_FALSE(cipher_result_no_ssl) << "Cipher selection should fail without SSL initialization";
}

TEST_F(TLSSSLTest, ProtocolVersionEnforcement) {
    // Test protocol version enforcement
    bool init_result = mock_tls_security->initializeSSL();
    EXPECT_TRUE(init_result) << "SSL initialization should succeed";
    
    // Test TLS 1.2 enforcement
    bool tls12_result = mock_tls_security->enforceTLSVersion(0x0303); // TLS 1.2
    EXPECT_TRUE(tls12_result) << "TLS 1.2 should be accepted";
    
    // Test TLS 1.3 enforcement
    bool tls13_result = mock_tls_security->enforceTLSVersion(0x0304); // TLS 1.3
    EXPECT_TRUE(tls13_result) << "TLS 1.3 should be accepted";
    
    // Test older TLS versions rejection
    bool tls11_result = mock_tls_security->enforceTLSVersion(0x0302); // TLS 1.1
    EXPECT_FALSE(tls11_result) << "TLS 1.1 should be rejected";
    
    bool tls10_result = mock_tls_security->enforceTLSVersion(0x0301); // TLS 1.0
    EXPECT_FALSE(tls10_result) << "TLS 1.0 should be rejected";
    
    bool ssl30_result = mock_tls_security->enforceTLSVersion(0x0300); // SSL 3.0
    EXPECT_FALSE(ssl30_result) << "SSL 3.0 should be rejected";
    
    // Test protocol enforcement without SSL initialization
    mock_tls_security->cleanupSSL();
    bool no_ssl_result = mock_tls_security->enforceTLSVersion(0x0303);
    EXPECT_FALSE(no_ssl_result) << "Protocol enforcement should fail without SSL initialization";
}

TEST_F(TLSSSLTest, ManInTheMiddlePrevention) {
    // Test man-in-the-middle prevention
    bool init_result = mock_tls_security->initializeSSL();
    EXPECT_TRUE(init_result) << "SSL initialization should succeed";
    
    // Test MITM prevention
    bool mitm_result = mock_tls_security->preventMITM();
    EXPECT_TRUE(mitm_result) << "MITM prevention should succeed";
    
    // Test MITM prevention without SSL initialization
    mock_tls_security->cleanupSSL();
    bool mitm_no_ssl_result = mock_tls_security->preventMITM();
    EXPECT_FALSE(mitm_no_ssl_result) << "MITM prevention should fail without SSL initialization";
}

TEST_F(TLSSSLTest, CertificateExpirationHandling) {
    // Test certificate expiration handling
    bool init_result = mock_tls_security->initializeSSL();
    EXPECT_TRUE(init_result) << "SSL initialization should succeed";
    
    // Test certificate expiration check
    std::string cert_data = generateTestCertificate();
    bool expiration_result = mock_tls_security->checkCertificateExpiration(cert_data);
    EXPECT_TRUE(expiration_result) << "Certificate expiration check should succeed";
    
    // Test expiration check without SSL initialization
    mock_tls_security->cleanupSSL();
    bool expiration_no_ssl_result = mock_tls_security->checkCertificateExpiration(cert_data);
    EXPECT_FALSE(expiration_no_ssl_result) << "Expiration check should fail without SSL initialization";
}

// Additional TLS/SSL tests
TEST_F(TLSSSLTest, TLSSSLPerformance) {
    // Test TLS/SSL performance
    const int num_operations = 1000;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Test SSL initialization performance
    for (int i = 0; i < num_operations; ++i) {
        mock_tls_security->initializeSSL();
        mock_tls_security->cleanupSSL();
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Calculate performance metrics
    double time_per_operation = static_cast<double>(duration.count()) / num_operations;
    
    // TLS/SSL operations should be fast
    EXPECT_LT(time_per_operation, 1000.0) << "TLS/SSL operations too slow: " << time_per_operation << " microseconds";
    
    std::cout << "TLS/SSL performance: " << time_per_operation << " microseconds per operation" << std::endl;
}

TEST_F(TLSSSLTest, TLSSSLAccuracy) {
    // Test TLS/SSL accuracy
    bool init_result = mock_tls_security->initializeSSL();
    EXPECT_TRUE(init_result) << "SSL initialization should succeed";
    
    // Test certificate validation accuracy
    std::string cert_data = generateTestCertificate();
    bool cert_result = mock_tls_security->validateCertificate(cert_data);
    EXPECT_TRUE(cert_result) << "Certificate validation should be accurate";
    
    // Test protocol version accuracy
    bool tls12_result = mock_tls_security->enforceTLSVersion(0x0303);
    EXPECT_TRUE(tls12_result) << "TLS 1.2 enforcement should be accurate";
    
    bool tls11_result = mock_tls_security->enforceTLSVersion(0x0302);
    EXPECT_FALSE(tls11_result) << "TLS 1.1 rejection should be accurate";
    
    // Test cipher selection accuracy
    bool cipher_result = mock_tls_security->selectStrongCipher();
    EXPECT_TRUE(cipher_result) << "Cipher selection should be accurate";
    
    // Test MITM prevention accuracy
    bool mitm_result = mock_tls_security->preventMITM();
    EXPECT_TRUE(mitm_result) << "MITM prevention should be accurate";
    
    // Test certificate expiration accuracy
    bool expiration_result = mock_tls_security->checkCertificateExpiration(cert_data);
    EXPECT_TRUE(expiration_result) << "Certificate expiration check should be accurate";
}

