package org.zaproxy.zap.extension.sequence;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.InvalidRedirectLocationException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.network.HttpRedirectionValidator;
import org.zaproxy.zap.network.HttpRequestConfig;

import java.io.IOException;

public class HttpRedirectFollower {

    public static final Logger logger = Logger.getLogger(HttpRedirectFollower.class);

    /**
     * Follows redirections using the response of the given {@code message}. The {@code validator} in the give request
     * configuration will be called for each redirection received. After the call to this method the given {@code message} will
     * have the contents of the last response received (possibly the response of a redirection).
     * <p>
     * The validator is notified of each message sent and received (first message and redirections followed, if any).
     *
     * @param message the message that will be sent, must not be {@code null}
     * @param requestConfig the request configuration that contains the validator responsible for validation of redirections,
     *            must not be {@code null}.
     * @throws IOException if an error occurred while sending the message or following the redirections
     * @see #isRedirectionNeeded(int)
     */
    public static void followRedirections(HttpMessage message, HttpRequestConfig requestConfig, HttpSender httpSender) throws IOException {
        HttpClient client = httpSender.getClient();

        HttpRedirectionValidator validator = requestConfig.getRedirectionValidator();
        validator.notifyMessageReceived(message);

        HttpMessage redirectMessage = message;
        int maxRedirections = client.getParams().getIntParameter(HttpClientParams.MAX_REDIRECTS, 100);
        for (int i = 0; i < maxRedirections && isRedirectionNeeded(redirectMessage.getResponseHeader().getStatusCode()); i++) {
            URI newLocation = extractRedirectLocation(redirectMessage);
            if (newLocation == null || !validator.isValid(newLocation)) {
                return;
            }

            redirectMessage = redirectMessage.cloneAll();
            redirectMessage.getRequestHeader().setURI(newLocation);

            if (isRequestRewriteNeeded(redirectMessage.getResponseHeader().getStatusCode())) {
                redirectMessage.getRequestHeader().setMethod(HttpRequestHeader.GET);
                redirectMessage.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, null);
                redirectMessage.getRequestHeader().setHeader(HttpHeader.CONTENT_LENGTH, null);
                redirectMessage.setRequestBody("");
            }

            httpSender.sendAndReceive(redirectMessage, false);
            validator.notifyMessageReceived(redirectMessage);

            // Update the response of the (original) message
            message.setResponseHeader(redirectMessage.getResponseHeader());
            message.setResponseBody(redirectMessage.getResponseBody());
        }
    }

    public static HttpRequestConfig getHttpRequestConfig(AbstractPlugin plugin) {
        HttpRequestConfig httpRequestConfig = HttpRequestConfig.builder().setRedirectionValidator(new HttpRedirectionValidator() {
            @Override
            public boolean isValid(URI redirection) {
                return true;
            }

            @Override
            public void notifyMessageReceived(HttpMessage message) {
                // Nothing to do with the message.
            }
        }).build();

        return httpRequestConfig;
    }

    /**
     * Tells whether or not a redirection is needed based on the given status code.
     * <p>
     * A redirection is needed if the status code is 301, 302, 303, 307 or 308.
     *
     * @param statusCode the status code that will be checked
     * @return {@code true} if a redirection is needed, {@code false} otherwise
     * @see #isRequestRewriteNeeded(int)
     */
    private static boolean isRedirectionNeeded(int statusCode) {
        switch (statusCode) {
            case 301:
            case 302:
            case 303:
            case 307:
            case 308:
                return true;
            default:
                return false;
        }
    }

    /**
     * Tells whether or not the (original) request of the redirection with the given status code, should be rewritten.
     * <p>
     * For status codes 301, 302 and 303 the request should be changed from POST to GET when following redirections (mimicking
     * the behaviour of browsers, which per <a href="https://tools.ietf.org/html/rfc7231#section-6.4">RFC 7231, Section 6.4</a>
     * is now OK).
     *
     * @param statusCode the status code that will be checked
     * @return {@code true} if the request should be rewritten, {@code false} otherwise
     * @see #isRedirectionNeeded(int)
     */
    private static boolean isRequestRewriteNeeded(int statusCode) {
        return statusCode == 301 || statusCode == 302 || statusCode == 303;
    }

    /**
     * Extracts a {@code URI} from the {@code Location} header of the given HTTP {@code message}.
     * <p>
     * If there's no {@code Location} header this method returns {@code null}.
     *
     * @param message the HTTP message that will processed
     * @return the {@code URI} created from the value of the {@code Location} header, might be {@code null}
     * @throws InvalidRedirectLocationException if the value of {@code Location} header is not a valid {@code URI}
     */
    private static URI extractRedirectLocation(HttpMessage message) throws InvalidRedirectLocationException {
        String location = message.getResponseHeader().getHeader(HttpHeader.LOCATION);
        if (location == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("No Location header found: " + message.getResponseHeader());
            }
            return null;
        }

        try {
            return new URI(message.getRequestHeader().getURI(), location, true);
        } catch (URIException ex) {
            throw new InvalidRedirectLocationException("Invalid redirect location: " + location, location, ex);
        }
    }
}
