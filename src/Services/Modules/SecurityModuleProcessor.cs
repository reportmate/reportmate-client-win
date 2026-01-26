
        /// <summary>
        /// Process certificates from Windows certificate stores
        /// </summary>
        private void ProcessCertificates(Dictionary<string, List<Dictionary<string, object>>> osqueryResults, SecurityData data)
        {
            if (!osqueryResults.TryGetValue("certificates", out var certificates) || certificates.Count == 0)
            {
                _logger.LogDebug("No certificate data available from osquery");
                return;
            }

            _logger.LogDebug("Processing {Count} certificates", certificates.Count);
            var now = DateTime.UtcNow;
            var thirtyDaysFromNow = now.AddDays(30);

            foreach (var cert in certificates)
            {
                try
                {
                    var certInfo = new CertificateInfo
                    {
                        CommonName = GetStringValue(cert, "common_name"),
                        Subject = GetStringValue(cert, "subject"),
                        Issuer = GetStringValue(cert, "issuer"),
                        SerialNumber = GetStringValue(cert, "serial"),
                        Thumbprint = GetStringValue(cert, "sha1"),
                        StoreName = GetStringValue(cert, "store"),
                        StoreLocation = GetStringValue(cert, "store_location"),
                        KeyAlgorithm = GetStringValue(cert, "key_algorithm"),
                        SigningAlgorithm = GetStringValue(cert, "signing_algorithm")
                    };

                    // Parse self-signed
                    var selfSigned = GetStringValue(cert, "self_signed");
                    certInfo.IsSelfSigned = selfSigned == "1" || selfSigned.Equals("true", StringComparison.OrdinalIgnoreCase);

                    // Parse key strength
                    var keyStrength = GetStringValue(cert, "key_strength");
                    if (!string.IsNullOrEmpty(keyStrength) && int.TryParse(keyStrength, out var keyLen))
                    {
                        certInfo.KeyLength = keyLen;
                    }

                    // Parse not_valid_before
                    var notValidBefore = GetStringValue(cert, "not_valid_before");
                    if (!string.IsNullOrEmpty(notValidBefore))
                    {
                        if (long.TryParse(notValidBefore, out var beforeTimestamp))
                        {
                            certInfo.NotBefore = DateTimeOffset.FromUnixTimeSeconds(beforeTimestamp).UtcDateTime;
                        }
                        else if (DateTime.TryParse(notValidBefore, out var beforeDate))
                        {
                            certInfo.NotBefore = beforeDate;
                        }
                    }

                    // Parse not_valid_after
                    var notValidAfter = GetStringValue(cert, "not_valid_after");
                    if (!string.IsNullOrEmpty(notValidAfter))
                    {
                        if (long.TryParse(notValidAfter, out var afterTimestamp))
                        {
                            certInfo.NotAfter = DateTimeOffset.FromUnixTimeSeconds(afterTimestamp).UtcDateTime;
                        }
                        else if (DateTime.TryParse(notValidAfter, out var afterDate))
                        {
                            certInfo.NotAfter = afterDate;
                        }
                    }

                    // Calculate expiry status
                    if (certInfo.NotAfter.HasValue)
                    {
                        certInfo.IsExpired = certInfo.NotAfter.Value < now;
                        certInfo.IsExpiringSoon = !certInfo.IsExpired && certInfo.NotAfter.Value <= thirtyDaysFromNow;
                        certInfo.DaysUntilExpiry = (int)(certInfo.NotAfter.Value - now).TotalDays;

                        if (certInfo.IsExpired)
                        {
                            certInfo.Status = "Expired";
                        }
                        else if (certInfo.IsExpiringSoon)
                        {
                            certInfo.Status = "ExpiringSoon";
                        }
                        else
                        {
                            certInfo.Status = "Valid";
                        }
                    }
                    else
                    {
                        certInfo.Status = "Unknown";
                    }

                    data.Certificates.Add(certInfo);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to parse certificate");
                }
            }

            _logger.LogInformation("Processed {Count} certificates - Expired: {Expired}, ExpiringSoon: {ExpiringSoon}, Valid: {Valid}",
                data.Certificates.Count,
                data.Certificates.Count(c => c.IsExpired),
                data.Certificates.Count(c => c.IsExpiringSoon),
                data.Certificates.Count(c => c.Status == "Valid"));
        }
    }
}