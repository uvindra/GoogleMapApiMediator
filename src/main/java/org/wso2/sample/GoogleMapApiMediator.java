package org.wso2.sample;


import com.damnhandy.uri.template.UriTemplate;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.config.SynapseConfiguration;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.endpoints.HTTPEndpoint;
import org.apache.synapse.mediators.AbstractMediator;
import org.apache.synapse.mediators.filters.FilterMediator;
import org.apache.synapse.mediators.base.SequenceMediator;
import org.apache.synapse.mediators.builtin.SendMediator;
import org.apache.synapse.rest.API;
import org.apache.synapse.rest.Resource;
import org.apache.synapse.transport.nhttp.NhttpConstants;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import javax.annotation.CheckForNull;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * This custom Mediator enables calling the Google Map API using the Client ID method, for users who purchase a licence
 * from Google[1]. Google will provide a Client ID and Cryptographic Private Key to users which needs to be passed
 * as property parameters to this mediator when it is engaged. Below example shows how to engage this mediator
 * in a sequence with the required Client ID and Private Key.
 *
 *      <sequence xmlns="http://ws.apache.org/ns/synapse" name="GoogleMapApiSequence">
 *          <class name="org.wso2.sample.GoogleMapApiMediator">
 *              <property name="PrivateKey" value="vNIXE0xscrmjlyV-12Nj_BvUPaw="/>
 *              <property name="ClientID" value="clientID"/>
 *          </class>
 *      </sequence>
 *
 * When engaging the mediator as above ensure that you substitute your own Private Key and Client ID values in the
 * respective properties.
 *
 * [1] https://developers.google.com/maps/documentation/geocoding/get-api-key#client-id
 *
 */

public class GoogleMapApiMediator extends AbstractMediator {
    private static final Log log = LogFactory.getLog(GoogleMapApiMediator.class);

    private String privateKey;
    private String clientId;

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    private static final String WILDCARD_RESOURCE_VALUE = "/*";
    private static final String CURRENT_API_KEY = "SYNAPSE_REST_API";
    private static final String RESOURCE_INVOKED_KEY = "API_ELECTED_RESOURCE";

    private static final String FILTER_MEDIATOR = "FilterMediator";
    private static final String SEND_MEDIATOR = "SendMediator";
    private static final String QUERY_PARAM_KEY_CLIENT = "client";
    private static final String QUERY_PARAM_KEY_SIGNATURE = "signature";

    class MediatorException extends Exception {
        MediatorException(String msg) {
            super(msg);
        }
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        if (privateKey == null) {
            log.error("Required Property 'privateKey' has not be defined in mediator");
            return triggerServerError(messageContext); // Interrupt execution flow
        }

        if (clientId == null) {
            log.error("Required Property 'clientId' has not be defined in mediator");
            return triggerServerError(messageContext); // Interrupt execution flow
        }

        String apiKey = (String) messageContext.getProperty(CURRENT_API_KEY);

        if (log.isDebugEnabled()) {
            log.debug("API Key available in message context: " + apiKey);
        }

        SynapseConfiguration synapseConfiguration = messageContext.getConfiguration();

        API api = synapseConfiguration.getAPI(apiKey);

        try {
            String completeURL = constructURLForSigning(api, messageContext);

            if (log.isDebugEnabled()) {
                log.debug("Complete endpoint URL: " + completeURL);
            }

            URL url = new URL(completeURL);
            String signature = signURL(url);

            if (log.isDebugEnabled()) {
                log.debug("Signed signature: " + signature);
            }

            appendClientAndSignature(messageContext, signature);

        } catch (MalformedURLException | MediatorException |
                NoSuchAlgorithmException | InvalidKeyException e) {
            log.error(e);
            return triggerServerError(messageContext);
        }

        return true;
    }

    /**
     * Setter function to set property privateKey. This function will be automatically called when this mediator is
     * engaged and will be set with the value of the corresponding property named 'privateKey' which should be defined
     * along side the use of the mediator
     * @param privateKey value of the Private Key
     */
    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Setter function to set property clientId. This function will be automatically called when this mediator is
     * engaged and will be set with the value of the corresponding property named 'clientId' which should be defined
     * along side the use of the mediator
     * @param clientId value of the Client ID
     */
    public void setClientID(String clientId) {
        this.clientId = clientId;
    }

    /**
     * Appends the 'client' and the calculated 'signature' query parameters to the URL path
     * @param messageContext Synapse message context
     * @param signature Signed URL signature
     */
    private void appendClientAndSignature(MessageContext messageContext, String signature) {
        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();

        String restURLPostFix = (String) axis2MessageContext.getProperty(NhttpConstants.REST_URL_POSTFIX);

        if (log.isDebugEnabled()) {
            log.debug("Original REST_URL_POSTFIX: " + restURLPostFix);
        }

        // Append the 'client' and 'signature' query parameters
        restURLPostFix += '&' + QUERY_PARAM_KEY_CLIENT + '=' + clientId + '&' +
                QUERY_PARAM_KEY_SIGNATURE + '=' + signature;

        if (log.isDebugEnabled()) {
            log.debug("Modified REST_URL_POSTFIX: " + restURLPostFix);
        }

        // Update REST_URL_POSTFIX property
        axis2MessageContext.setProperty(NhttpConstants.REST_URL_POSTFIX, restURLPostFix);
    }


    /**
     * Trigger an internal server error to denote that an unrecoverable issue has been encountered by the mediator.
     * This can be used to interrupt the execution flow.
     *
     * @param messageContext Synapse message context
     * @return always returns false
     */
    private boolean triggerServerError(MessageContext messageContext) {
        messageContext.setProperty(SynapseConstants.RESPONSE, "true");
        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext).
                                                                                            getAxis2MessageContext();
        axis2MessageContext.removeProperty(NhttpConstants.NO_ENTITY_BODY);
        axis2MessageContext.setProperty(NhttpConstants.HTTP_SC, "500");

        messageContext.setTo(null);
        SendMediator sendMediator = new SendMediator();
        sendMediator.mediate(messageContext);

        return false;
    }

    /**
     * Get endpoint URL configured in the API
     *
     * @param api Model representing the Synapse API object instance that this mediator is being engaged from
     * @param messageContext Synapse message context
     * @return Endpoint URL string
     */
    private String getEndpointURL(API api, MessageContext messageContext) throws MediatorException {
        Resource[] resources = api.getResources();

        if (resources.length > 0) {
            // In API Manager all resources share the same endpoint URL, so extracting the first resource is sufficient
            Resource resource = resources[0];
            SequenceMediator inSequence = resource.getInSequence();

            // Get list of mediators configured within the inSequence
            List<Mediator> mediators = inSequence.getList();

            for (Mediator mediator : mediators) {
                if (FILTER_MEDIATOR.equals(mediator.getType())) { // Select the Filter mediator
                    FilterMediator filterMediator = (FilterMediator) mediator;

                    List<Mediator> filterMediatorList;

                    // Depending on whether a PRODUCTION or SANDBOX key has been sent, select the appropriately
                    // configure endpoint

                    if (filterMediator.test(messageContext)) { // Select mediators defined within then clause
                        filterMediatorList = filterMediator.getList();
                    } else { // Select mediators defined within else clause
                        filterMediatorList = filterMediator.getElseMediator().getList();
                    }

                    for (Mediator childMediator : filterMediatorList) {
                        if (SEND_MEDIATOR.equals(childMediator.getType())) { // Select Send mediator
                            SendMediator sendMediator = (SendMediator) childMediator;

                            // Get the URL of the HTTP Endpoint that is configured in the Send mediator
                            HTTPEndpoint httpEndpoint = (HTTPEndpoint) sendMediator.getEndpoint();
                            UriTemplate uriTemplate = httpEndpoint.getUriTemplate();

                            return uriTemplate.getTemplate();
                        }
                    }
                }
            }
        }

        throw new MediatorException("Could not locate endpoint URL in synapse configuration");
    }

    /**
     * Extract string containing query params that were sent along with the invocation. This will have a format similar
     * to 'q1=v1&q2=v2'
     *
     * @param messageContext Synapse message context
     * @return Query params string if exists else null
     */
    @CheckForNull
    private String getQueryParamsString(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();

        String restURLPostFix = (String) axis2MessageContext.getProperty(NhttpConstants.REST_URL_POSTFIX);

        if (!StringUtils.isEmpty(restURLPostFix)) {
            if (restURLPostFix.contains("?") && !restURLPostFix.endsWith("?")) {
                return restURLPostFix.substring(restURLPostFix.indexOf("?") + 1);
            }
        }

        return null;
    }

    /**
     * Return string representation of URL which will be used for signing, having format such as,
     *
     *    https://maps.googleapis.com/maps/api/geocode/json?address=New+York&client=clientID
     *
     * This has the format,
     *
     *    <Endpoint URL>?<Query Params Sent in Request>&<Client ID Query Param>
     *
     * @param api Model representing the Synapse API object instance that this mediator is being engaged from
     * @param messageContext Synapse message context
     * @return String representation of URL
     */
    private String constructURLForSigning(API api, MessageContext messageContext) throws MediatorException {
        String endpointURL = getEndpointURL(api, messageContext);

        if (log.isDebugEnabled()) {
            log.debug("Endpoint URL defined in API: " + endpointURL);
        }

        String resourceInvoked = (String) messageContext.getProperty(RESOURCE_INVOKED_KEY);

        if (log.isDebugEnabled()) {
            log.debug("Resource invoked: " + resourceInvoked);
        }

        // If the API resource that was invoked is not a wild card resource, we need to append the API resource
        // to the endpointURL to arrive at the complete URL
        if (!WILDCARD_RESOURCE_VALUE.equals(resourceInvoked)) {
            endpointURL = endpointURL + resourceInvoked;

            if (log.isDebugEnabled()) {
                log.debug("Endpoint URL with appended resource: " + endpointURL);
            }
        }

        // Retrieve string from URL that consists of the query params that were sent(example: "q1=v1&q2=v2")
        String queryParamsString = getQueryParamsString(messageContext);

        if (log.isDebugEnabled()) {
            log.debug("Query Parameters: " + queryParamsString);
        }

        // Append query parameters that were sent(if they exist) and the clientID query parameter to the endpointURL
        if (queryParamsString !=  null) {
            return endpointURL + '?' + queryParamsString + '&' + QUERY_PARAM_KEY_CLIENT + '=' + clientId;
        } else { // Could not detect Query Params
            return endpointURL + '?' + QUERY_PARAM_KEY_CLIENT + '=' + clientId;
        }
    }

    /**
     * Sign a given URL with the configured private key to generate the signature
     *
     * @param url URL to be signed
     * @return Signed URL signature
     * @throws NoSuchAlgorithmException if HmacSHA1 algorithm cannot be found
     * @throws InvalidKeyException if private key is invalid
     */
    private String signURL(URL url) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] key = convertBase64KeyToBinary();

        // Construct resource to be signed
        String resource = url.getPath() + '?' + url.getQuery();

        // Get an HMAC-SHA1 signing key from the raw key bytes
        SecretKeySpec sha1Key = new SecretKeySpec(key, HMAC_SHA1_ALGORITHM);

        // Get an HMAC-SHA1 Mac instance and initialize it with the HMAC-SHA1 key
        Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
        mac.init(sha1Key);

        // compute the binary signature for the request
        byte[] sigBytes = mac.doFinal(resource.getBytes());

        // base 64 encode the binary signature
        String signature = Base64.getEncoder().encodeToString(sigBytes);

        // convert the signature to 'web safe' base 64
        signature = signature.replace('+', '-');
        signature = signature.replace('/', '_');

        return signature;
    }

    /**
     * Convert web safe base64 string to binary
     *
     * @return Converted binary string
     */
    private byte[] convertBase64KeyToBinary() {
        // Convert the key from 'web safe' base 64 to standard base 64
        String base64Value = privateKey.replace('-', '+');
        base64Value = base64Value.replace('_', '/');

        return Base64.getDecoder().decode(base64Value);
    }
}


