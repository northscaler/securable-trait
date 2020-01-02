'use strict'

/**
 * Returns whether the given principal can take the given action on an instance of the given securable.
 *
 * @function GrantsDecisionFn
 * @param {Object} arg The argument to be deconstructed.
 * @param {string} arg.principal The principal attempting take `action` on `securable`, given optional `data`.
 * @param {string} arg.action The action being taken.
 * @param {string} arg.securable The securable access to which is being controlled.
 * @param {any} [arg.data] Optional, arbitrary data that may be used to make an access control decision.
 * @return {boolean} Whether `principal` is granted and not explicitly denied the ability to take `action`, given optional `data`.
 */

/**
 * Returns whether the given role is explicitly denied the ability to invoke the given method on an instance of the given class.
 * If methods are accessors with property name `x`, then the method name is `get ${x}` or `set ${x}`.
 *
 * @function DeniesDecisionFn
 * @param {Object} arg The argument to be deconstructed.
 * @param {string} arg.principal The principal attempting take `action` on `securable`, given optional `data`.
 * @param {string} arg.action The action being taken.
 * @param {string} arg.securable The securable access to which is being controlled.
 * @param {any} [arg.data] Optional, arbitrary data that may be used to make an access control decision.
 * @return {boolean} Whether `principal` is explicitly denied the ability to take `action`, given optional `data`.
 */

/**
 * @typedef AccessControlStrategy
 * @type {Object}
 * @property {GrantsDecisionFn} grants
 * @property {DeniesDecisionFn} denies
 */
