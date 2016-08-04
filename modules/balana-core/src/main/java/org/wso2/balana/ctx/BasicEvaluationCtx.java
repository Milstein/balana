/*
 *  Copyright (c) WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.balana.ctx;

import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Stack;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Node;
import org.wso2.balana.AbstractPolicy;
import org.wso2.balana.MatchResult;
import org.wso2.balana.PDPConfig;
import org.wso2.balana.PolicyReference;
import org.wso2.balana.PolicySet;
import org.wso2.balana.PolicyTreeElement;
import org.wso2.balana.ProcessingException;
import org.wso2.balana.XACMLConstants;
import org.wso2.balana.attr.BagAttribute;
import org.wso2.balana.attr.DateAttribute;
import org.wso2.balana.attr.DateTimeAttribute;
import org.wso2.balana.attr.DecisionAttribute;
import org.wso2.balana.attr.TimeAttribute;
import org.wso2.balana.cond.EvaluationResult;
import org.wso2.balana.ctx.xacml3.Result;
import org.wso2.balana.finder.RevocationFinder;
import org.wso2.balana.reduction.ReductionGraph;

/**
 * Implementation of <code>EvaluationCtx</code>. This implements some generic
 * methods that commons to most of the implementations
 */
public abstract class BasicEvaluationCtx implements EvaluationCtx, Cloneable {

	/**
	 * the revocation finder to use
	 */
	private RevocationFinder rFinder;

	/**
	 * flag that indicates if the revocation finder is deactivated.
	 */
	private boolean rfinderActive = true;

	/**
	 * The request data. A map of <code>Set</code>s of
	 * <code>RequestElement</code>s keyed by the attribute category
	 * <code>String</code>s.
	 */
	private HashMap<URI, Set<RequestElement>> requestElements = null;

	/**
	 * the cached delegation decision value
	 */
	private int delegationDecision;

	/**
	 * the delegation depth value
	 */
	private int delegationDepth;

	/**
	 * the cached current date, time, and date time, which we may or may not be
	 * using depending on how this object was constructed
	 */
	protected DateAttribute currentDate;
	protected TimeAttribute currentTime;
	protected DateTimeAttribute currentDateTime;

	/**
	 * TODO what is this?
	 */
	protected boolean useCachedEnvValues = false;

	/**
	 * a stack of parent <code>PolicySet</code>s.
	 */
	private Stack<PolicyTreeElement> parentPolicySets;

	/**
	 * a stack of <code>ReductionGraph</code>s.
	 */
	private Stack<ReductionGraph> reductionGraphs;

	/**
	 * the set of deactivated policies
	 */
	private Set<URI> inactivePolicyIds;

	/**
	 * the DOM root the original RequestContext document
	 */
	protected Node requestRoot;

	/**
	 * Represents a XACML request made to the PDP
	 */
	protected AbstractRequestCtx requestCtx;

	/**
	 * PDP configurations
	 */
	protected PDPConfig pdpConfig;

	/**
	 * logger
	 */
	private static Log logger = LogFactory.getLog(BasicEvaluationCtx.class);

	/**
	 * Create a context for an administrative request from this context.
	 * 
	 * @param decision
	 *            The decision code corresponding to those in the
	 *            <code>Result</code> class.
	 * @param delegate
	 *            The delegate in this request (a set containing a single
	 *            <code>RequestElement</code>).
	 * 
	 * @return An administrative context for this context.
	 * @throws CloneNotSupportedException
	 */
	public EvaluationCtx createAdminCtx(int decision,
			Set<RequestElement> delegate) throws CloneNotSupportedException {
		if (decision == Result.DECISION_INDETERMINATE_PERMIT
				|| decision == Result.DECISION_INDETERMINATE
				|| decision == Result.DECISION_NOT_APPLICABLE) {
			throw new ProcessingException("Invalid decision value for an"
					+ " administrative request");
		}

		// First copy the old context.
		BasicEvaluationCtx adminCtx = null;
		adminCtx = (BasicEvaluationCtx) this.clone();

		// Now set the new values ...
		adminCtx.delegationDecision = decision;
		adminCtx.delegationDepth = this.delegationDepth + 1;

		// ... and modify the requestElements accordingly
		HashMap<URI, Set<RequestElement>> newREmap = new HashMap<URI, Set<RequestElement>>();

		// get out the delegation relevant information
		// and remove the old
		adminCtx.requestElements.remove(XACMLConstants.DELEGATION_INFO);
		adminCtx.requestElements.remove(XACMLConstants.DELEGATE);

		// modify the rest so category * becomes category
		// urn:oasis:names:tc:xacml:3.0:attribute-category:delegated:*
		Iterator<Entry<URI, Set<RequestElement>>> iter = adminCtx.requestElements
				.entrySet().iterator();
		while (iter.hasNext()) {
			Entry<URI, Set<RequestElement>> entry = iter.next();
			Set<RequestElement> requestElementCategory = entry.getValue();
			Iterator<RequestElement> iter2 = requestElementCategory.iterator();
			HashSet<RequestElement> newREset = new HashSet<RequestElement>();
			URI category = null;
			while (iter2.hasNext()) {
				RequestElement oldRe = iter2.next();
				category = oldRe.getCategory();
				if (category.toString().startsWith(XACMLConstants.DELEGATED)) {
					newREset.add(oldRe);
				} else { // add the delegated part to the category
					category = URI.create(XACMLConstants.DELEGATED
							+ category.toString());
					// this URI must be valid, since the old category was
					RequestElement newRe = new RequestElement(category,
							oldRe.getAttributes());
					newREset.add(newRe);
				}
			}
			newREmap.put(category, newREset);
		}

		// put in the new delegate
		newREmap.put(URI.create(XACMLConstants.DELEGATE), delegate);

		// put in the new delegation info

		// then create the correct DelegationInfo category
		DecisionAttribute delegationDecision = new DecisionAttribute(decision);
		Set<Attribute> delegationInfoAttrs = new HashSet<Attribute>();
		delegationInfoAttrs.add(delegationDecision);
		RequestElement delegationInfo = new RequestElement(
				URI.create(XACMLConstants.DELEGATION_INFO), delegationInfoAttrs);
		Set<RequestElement> delegationInfoSet = new HashSet<RequestElement>();
		delegationInfoSet.add(delegationInfo);
		// and put it into the new request elements map
		newREmap.put(URI.create(XACMLConstants.DELEGATION_INFO),
				delegationInfoSet);

		// now we are done, copy the newREmap to the requestElements
		adminCtx.requestElements = newREmap;

		return adminCtx;
	}

	/**
	 * Returns the DOM root of the original RequestType XML document.
	 *
	 * @return the DOM root node
	 */
	public Node getRequestRoot() {
		return requestRoot;
	}

	/**
	 * TODO
	 * 
	 * @return
	 */
	public boolean isSearching() {
		return false;
	}

	/**
	 * Returns the value for the current time. The current time, current date,
	 * and current dateTime are consistent, so that they all represent the same
	 * moment. If this is the first time that one of these three values has been
	 * requested, and caching is enabled, then the three values will be resolved
	 * and stored.
	 * <p/>
	 * Note that the value supplied here applies only to dynamically resolved
	 * values, not those supplied in the Request. In other words, this always
	 * returns a dynamically resolved value local to the PDP, even if a
	 * different value was supplied in the Request. This is handled correctly
	 * when the value is requested by its identifier.
	 *
	 * @return the current time
	 */
	public synchronized TimeAttribute getCurrentTime() {
		long millis = dateTimeHelper();

		if (useCachedEnvValues)
			return currentTime;
		else
			return new TimeAttribute(new Date(millis));
	}

	/**
	 * Returns the value for the current date. The current time, current date,
	 * and current dateTime are consistent, so that they all represent the same
	 * moment. If this is the first time that one of these three values has been
	 * requested, and caching is enabled, then the three values will be resolved
	 * and stored.
	 * <p/>
	 * Note that the value supplied here applies only to dynamically resolved
	 * values, not those supplied in the Request. In other words, this always
	 * returns a dynamically resolved value local to the PDP, even if a
	 * different value was supplied in the Request. This is handled correctly
	 * when the value is requested by its identifier.
	 *
	 * @return the current date
	 */
	public synchronized DateAttribute getCurrentDate() {
		long millis = dateTimeHelper();

		if (useCachedEnvValues)
			return currentDate;
		else
			return new DateAttribute(new Date(millis));
	}

	/**
	 * Returns the value for the current dateTime. The current time, current
	 * date, and current dateTime are consistent, so that they all represent the
	 * same moment. If this is the first time that one of these three values has
	 * been requested, and caching is enabled, then the three values will be
	 * resolved and stored.
	 * <p/>
	 * Note that the value supplied here applies only to dynamically resolved
	 * values, not those supplied in the Request. In other words, this always
	 * returns a dynamically resolved value local to the PDP, even if a
	 * different value was supplied in the Request. This is handled correctly
	 * when the value is requested by its identifier.
	 *
	 * @return the current dateTime
	 */
	public synchronized DateTimeAttribute getCurrentDateTime() {
		long millis = dateTimeHelper();

		if (useCachedEnvValues)
			return currentDateTime;
		else
			return new DateTimeAttribute(new Date(millis));
	}

	public AbstractRequestCtx getRequestCtx() {
		return requestCtx;
	}

	/**
	 * Returns the attribute value(s) retrieved using the given XPath
	 * expression.
	 *
	 * @param path
	 *            the XPath expression to search
	 * @param type
	 *            the type of the attribute value(s) to find
	 * @param category
	 *            the category the attribute value(s) must be in
	 * @param contextSelector
	 *            the selector to find the context to apply XPath expression if
	 *            this is null, applied for default content
	 * @param xpathVersion
	 *            the version of XPath to use
	 *
	 * @return a result containing a bag either empty because no values were
	 *         found or containing at least one value, or status associated with
	 *         an Indeterminate result
	 */

	public EvaluationResult getAttribute(String path, URI type, URI category,
			URI contextSelector, String xpathVersion) {

		if (pdpConfig.getAttributeFinder() != null) {
			return pdpConfig.getAttributeFinder().findAttribute(path, type,
					this, xpathVersion);
		} else {
			logger.warn("Context tried to invoke AttributeFinder but was "
					+ "not configured with one");

			return new EvaluationResult(BagAttribute.createEmptyBag(type));
		}
	}

	/**
	 * Get the decision.
	 * 
	 * @return The <code>int</code> value of the decision according to the
	 *         <code>Result</code> class.
	 */
	public int getDecision() {
		return this.delegationDecision;
	}

	/**
	 * Get the delegation depth.
	 * 
	 * @return The <code>int</code> value specifying the number of nodes in the
	 *         reduction graph until now (not including this one).
	 */
	public int getDelegationDepth() {
		return this.delegationDepth;
	}

	/**
	 * Save the parent <code>PolicySet</code> in this evaluation context for
	 * doing reduction of delegated policies if that becomes necessary.
	 * 
	 * @param pps
	 *            the parent policy set
	 */
	public void saveParentPolicySet(AbstractPolicy pps) {
		if (pps instanceof PolicySet) {
			this.parentPolicySets.push(pps);
		} else if (pps instanceof PolicyReference) {
			PolicyReference pr = (PolicyReference) pps;
			if (pr.getReferenceType() != PolicyReference.POLICYSET_REFERENCE) {
				// this should never happen
				throw new RuntimeException("Tried to save a Reference "
						+ "to a Policy as a PolicySet");
			}
			this.parentPolicySets.push(pps);
		} else {
			throw new RuntimeException("Tried to save "
					+ this.getClass().getName() + " as a PolicySet");
		}
	}

	/**
	 * Returns the root <code>PolicySet</code> for this evaluation context. If
	 * there is none, return null.
	 *
	 * @return the root policy set or null.
	 */
	public AbstractPolicy getParentPolicySet() {
		if (!this.parentPolicySets.empty()) {
			return (AbstractPolicy) this.parentPolicySets.peek();
		}
		return null;
	}

	/**
	 * Remove the current parent <code>PolicySet</code> from the stack of parent
	 * policy sets.
	 */
	public void popParentPolicySet() {
		if (!this.parentPolicySets.isEmpty()) {
			this.parentPolicySets.pop();
		}
	}

	/**
	 * Create a reduction graph for the current parent PolicySet.
	 *
	 */
	public void createReductionGraph() {
		if (getParentPolicySet() != null) {
			this.reductionGraphs.push(new ReductionGraph(getParentPolicySet()));
		}
	}

	/**
	 * @return The current reduction graph or null if there is none.
	 */
	public ReductionGraph getReductionGraph() {
		if (this.reductionGraphs != null && !this.reductionGraphs.empty()) {
			return (ReductionGraph) this.reductionGraphs.peek();
		}
		return null;
	}

	/**
	 * Remove the current <code>ReductionGraph</code> from the stack.
	 */
	public void popReductionGraph() {
		if (!this.reductionGraphs.isEmpty()) {
			this.reductionGraphs.pop();
		}
	}

	/**
	 * Checks whether a <code>Policy</code> or <code>PolicySet</code> supports a
	 * revocation of a specific Policy of PolicySet in this context.
	 * 
	 * @param supporting
	 *            The policy or policy set that could support a revocation.
	 * @param candidate
	 *            The id of the policy or policy set that is candidate for
	 *            revocation.
	 * 
	 * @return true if the policy/policy set supports a revocation, false
	 *         otherwise.
	 */
	public boolean supportsRevocation(AbstractPolicy supporting, URI candidate) {
		if (this.rFinder != null && this.rfinderActive) {
			// deactivate revocation finder to avoid infinite loops
			// of policies revoking themselves
			this.rfinderActive = false;
			boolean result = this.rFinder.supportsRevocation(supporting,
					candidate, this);
			this.rfinderActive = true;
			return result;
		}
		// since there is no revocation finder, no policy can be
		// revoked.
		logger.warn("Context tried to invoke RevocationFinder but was "
				+ "not configured with one");
		return false;
	}

	/**
	 * Add new inactive PolicyId to the Map
	 * 
	 * @param policyId
	 *            the id of the new inactive policy
	 */
	public void addInactivePolicyId(URI policyId) {
		this.inactivePolicyIds.add(policyId);
	}

	/**
	 * Return an unmodifiable <code>Set</code> of <code>URI</code>s of inactive
	 * policies
	 * 
	 * @return the inactive policies
	 */
	public Set<URI> getInactivePolicyIds() {
		return Collections.unmodifiableSet(new HashSet<URI>(
				this.inactivePolicyIds));
	}

	/**
	 * Signal a new event to this EvaluationCtx. BasicEvaluationCtx does nothing
	 * with this signal.
	 * 
	 * @param element
	 *            The new event.
	 */
	public void newEvent(Object element) {
		// BasicEvaluationCtx does nothing with this signal.
	}

	/**
	 * Signal that an event has finished and pass the result. BasicEvaluationCtx
	 * does nothing with this signal.
	 * 
	 * @param result
	 *            The result of the finished event.
	 */
	public void closeCurrentEvent(AbstractResult result) {
		// BasicEvaluationCtx does nothing with this signal.
	}

	/**
	 * Signal that an event has finished and pass the result. BasicEvaluationCtx
	 * does nothing with this signal.
	 * 
	 * @param result
	 *            The result of the finished event.
	 */
	public void closeCurrentEvent(MatchResult result) {
		// BasicEvaluationCtx does nothing with this signal.
	}

	/**
	 * Signal that an event has finished and pass the result which is a
	 * <code>EvaluationResult</code> BasicEvaluationCtx does nothing with this
	 * signal.
	 * 
	 * @param result
	 *            The result of the finished event.
	 */
	public void closeCurrentEvent(EvaluationResult result) {
		// BasicEvaluationCtx does nothing with this signal.
	}

	/**
	 * Signal that an event has finished with a <code>String</code> message.
	 * BasicEvaluationCtx does nothing with this signal.
	 * 
	 * @param message
	 *            The message.
	 */
	public void closeCurrentEvent(String message) {
		// BasicEvaluationCtx does nothing with this signal.
	}

	/**
	 * Signal that an event has finished with no result. BasicEvaluationCtx does
	 * nothing with this signal.
	 */
	public void closeCurrentEvent() {
		// BasicEvaluationCtx does nothing with this signal.
	}

	/**
	 * Private helper that figures out if we need to resolve new values, and
	 * returns either the current moment (if we're not caching) or -1 (if we are
	 * caching)
	 * 
	 * @return current moment as long value
	 */
	private long dateTimeHelper() {
		// if we already have current values, then we can stop (note this
		// always means that we're caching)
		if (currentTime != null)
			return -1;

		// get the current moment
		Date time = new Date();
		long millis = time.getTime();

		// if we're not caching then we just return the current moment
		if (!useCachedEnvValues) {
			return millis;
		} else {
			// we're caching, so resolve all three values, making sure
			// to use clean copies of the date object since it may be
			// modified when creating the attributes
			currentTime = new TimeAttribute(time);
			currentDate = new DateAttribute(new Date(millis));
			currentDateTime = new DateTimeAttribute(new Date(millis));
		}

		return -1;
	}

	/**
	 * Private helper that calls the finder if it's non-null, or else returns an
	 * empty bag
	 *
	 * @param type
	 *            the type of the attribute value(s) to find
	 * @param id
	 *            the id of the attribute value(s) to find
	 * @param issuer
	 *            the issuer of the attribute value(s) to find or null
	 * @param category
	 *            the category the attribute value(s) must be in
	 *
	 * @return a result containing a bag either empty because no values were
	 *         found or containing at least one value, or status associated with
	 *         an Indeterminate result
	 */
	protected EvaluationResult callHelper(URI type, URI id, String issuer,
			URI category) {
		if (pdpConfig.getAttributeFinder() != null) {
			return pdpConfig.getAttributeFinder().findAttribute(type, id,
					issuer, category, this);
		} else {
			if (logger.isWarnEnabled()) {
				logger.warn("Context tried to invoke AttributeFinder but was "
						+ "not configured with one");
			}

			return new EvaluationResult(BagAttribute.createEmptyBag(type));
		}
	}

	// /**
	// * The clone method
	// *
	// * @return a copy of this object.
	// *
	// */
	// public Object clone() {
	// try {
	// BasicEvaluationCtx clone = (BasicEvaluationCtx) super.clone();
	// if (this.aFinder != null) {
	// clone.aFinder = (AttributeFinder) this.aFinder.clone();
	// }
	// clone.afinderActive = this.afinderActive;
	// if (this.rFinder != null) {
	// clone.rFinder = (RevocationFinder) this.rFinder.clone();
	// }
	// clone.rfinderActive = this.rfinderActive;
	// if (this.requestRoot != null) {
	// clone.requestRoot = this.requestRoot.cloneNode(true);
	// } else {
	// clone.requestRoot = null;
	// }
	//
	// // deep copy of the requestElements
	// clone.requestElements = new HashMap<URI, Set<RequestElement>>();
	// Iterator<URI> iter = this.requestElements.keySet().iterator();
	// while (iter.hasNext()) {
	// URI key = URI.create(iter.next().toString());
	// Set<RequestElement> res = new HashSet<RequestElement>();
	// Iterator<RequestElement> iter2 = this.requestElements.get(key)
	// .iterator();
	// while (iter2.hasNext()) {
	// res.add((RequestElement) iter2.next().clone());
	// }
	// clone.requestElements.put(key, res);
	// }
	//
	// clone.delegationDecision = this.delegationDecision;
	// clone.delegationDepth = this.delegationDepth;
	// clone.resourceId = this.resourceId;
	//
	// // deep copy of the included attributes
	// clone.includedAttributes = new HashSet<RequestElement>();
	// Iterator<RequestElement> iter3 = this.includedAttributes.iterator();
	// while (iter3.hasNext()) {
	// RequestElement element = iter3.next();
	// clone.includedAttributes.add((RequestElement) element.clone());
	// }
	// synchronized (clone) {
	// clone.scope = this.scope;
	// clone.currentDate = this.currentDate;
	// clone.currentTime = this.currentTime;
	// clone.currentDateTime = this.currentDateTime;
	// clone.useCachedEnvValues = this.useCachedEnvValues;
	// }
	// // clone.parentPolicySets = (Stack<PolicyTreeElement>)
	// // this.parentPolicySets.clone(); //
	// clone.parentPolicySets = new Stack<PolicyTreeElement>();
	// Collections.copy(parentPolicySets, this.parentPolicySets);
	// // clone.reductionGraphs = (Stack<ReductionGraph>)
	// // this.reductionGraphs.clone();
	// clone.reductionGraphs = new Stack<ReductionGraph>();
	// Collections.copy(reductionGraphs, this.reductionGraphs);
	// clone.inactivePolicyIds = new HashSet<URI>(this.inactivePolicyIds);
	// return clone;
	// } catch (CloneNotSupportedException e) {// This should never happen
	// throw new RuntimeException("Couldn't clone BasicEvaluationCtx");
	// }
	// }

}
