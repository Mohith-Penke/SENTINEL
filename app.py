def check_ssl_certificate(url):
    """Real TLS certificate validation with safe diagnostic handling."""

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    try:
        port = parsed.port or 443
    except ValueError:
        return {
            "checked": True,
            "https": parsed.scheme.lower() == "https",
            "valid": False,
            "hostname_match": False,
            "trusted": False,
            "expired": None,
            "expires_at": None,
            "valid_from": None,
            "days_remaining": None,
            "issuer": None,
            "subject": None,
            "tls_version": None,
            "cipher": None,
            "certificate_version": None,
            "error": "Invalid HTTPS port.",
            "security_message": "The HTTPS port is invalid."
        }

    now = datetime.now(timezone.utc)

    result = {
        "checked": True,
        "https": parsed.scheme.lower() == "https",
        "valid": False,
        "hostname_match": False,
        "trusted": False,
        "expired": None,
        "expires_at": None,
        "valid_from": None,
        "days_remaining": None,
        "issuer": None,
        "subject": None,
        "tls_version": None,
        "cipher": None,
        "certificate_version": None,
        "error": None,
        "security_message": None,
    }

    if parsed.scheme.lower() != "https":
        result["error"] = "The website is not using HTTPS/TLS."
        result["security_message"] = (
            "This website does not establish an HTTPS/TLS connection."
        )
        return result

    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection(
            (host, port),
            timeout=5
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=host
            ) as tls_socket:

                cert = tls_socket.getpeercert()

                result["trusted"] = True
                result["hostname_match"] = True
                result["tls_version"] = tls_socket.version()

                cipher_info = tls_socket.cipher()

                if cipher_info:
                    result["cipher"] = cipher_info[0]

                cert_version = cert.get("version")

                if cert_version is not None:
                    result["certificate_version"] = (
                        "v" + str(cert_version + 1)
                    )

                # -------------------------------------------------
                # CERTIFICATE VALID FROM
                # -------------------------------------------------

                not_before = cert.get("notBefore")

                if not_before:
                    try:
                        issued = datetime.strptime(
                            not_before,
                            "%b %d %H:%M:%S %Y %Z"
                        ).replace(
                            tzinfo=timezone.utc
                        )

                        result["valid_from"] = issued.isoformat()

                    except Exception:
                        result["valid_from"] = None

                # -------------------------------------------------
                # CERTIFICATE EXPIRY
                # -------------------------------------------------

                not_after = cert.get("notAfter")

                if not_after:
                    try:
                        expiry = datetime.strptime(
                            not_after,
                            "%b %d %H:%M:%S %Y %Z"
                        ).replace(
                            tzinfo=timezone.utc
                        )

                        result["expires_at"] = expiry.isoformat()

                        result["expired"] = (
                            expiry <= now
                        )

                        result["days_remaining"] = max(
                            0,
                            (expiry - now).days
                        )

                    except Exception:
                        result["expired"] = None

                # -------------------------------------------------
                # ISSUER
                # -------------------------------------------------

                issuer_parts = []

                for group in cert.get("issuer", ()):
                    for key, value in group:

                        if key in (
                            "organizationName",
                            "commonName"
                        ):
                            issuer_parts.append(
                                str(value)
                            )

                if issuer_parts:
                    result["issuer"] = " / ".join(
                        dict.fromkeys(issuer_parts)
                    )

                # -------------------------------------------------
                # SUBJECT
                # -------------------------------------------------

                subject_parts = []

                for group in cert.get("subject", ()):
                    for key, value in group:

                        if key in (
                            "commonName",
                            "organizationName"
                        ):
                            subject_parts.append(
                                str(value)
                            )

                if subject_parts:
                    result["subject"] = " / ".join(
                        dict.fromkeys(subject_parts)
                    )

                # -------------------------------------------------
                # FINAL CERTIFICATE VERDICT
                # -------------------------------------------------

                result["valid"] = (
                    result["trusted"]
                    and result["hostname_match"]
                    and result["expired"] is False
                )

                if result["valid"]:

                    result["security_message"] = (
                        "Valid HTTPS certificate: trusted, "
                        "hostname matched, and certificate is "
                        "currently within its validity period."
                    )

                elif result["expired"]:

                    result["error"] = (
                        "The TLS certificate has expired."
                    )

                    result["security_message"] = (
                        "The certificate exists but has expired."
                    )

                else:

                    result["security_message"] = (
                        "The HTTPS certificate could not be fully "
                        "validated."
                    )

                return result

    except ssl.CertificateError:

        result["hostname_match"] = False
        result["trusted"] = False
        result["error"] = (
            "Certificate hostname verification failed."
        )
        result["security_message"] = (
            "The certificate does not match the requested hostname."
        )

    except ssl.SSLCertVerificationError as exc:

        result["trusted"] = False
        result["error"] = (
            "The TLS certificate could not be trusted or is invalid."
        )

        if getattr(exc, "verify_message", None):
            result["verification_error"] = str(
                exc.verify_message
            )

        result["security_message"] = (
            "The certificate validation failed during the TLS handshake."
        )

    except (socket.timeout, TimeoutError):

        result["error"] = (
            "TLS certificate check timed out."
        )

        result["security_message"] = (
            "The server did not respond to the certificate check in time."
        )

    except socket.gaierror:

        result["error"] = (
            "The website hostname could not be resolved."
        )

        result["security_message"] = (
            "The domain could not be resolved for certificate validation."
        )

    except ConnectionError:

        result["error"] = (
            "The HTTPS connection could not be established."
        )

        result["security_message"] = (
            "The server could not establish a secure HTTPS connection."
        )

    except OSError:

        result["error"] = (
            "The TLS certificate could not be checked."
        )

        result["security_message"] = (
            "The server could not complete the TLS certificate check."
        )

    except Exception as exc:

        result["error"] = (
            "TLS certificate check failed: "
            + exc.__class__.__name__
            + "."
        )

        result["security_message"] = (
            "The certificate could not be fully evaluated."
        )

    return result
