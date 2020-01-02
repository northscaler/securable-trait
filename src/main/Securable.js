'use strict'

const { Trait } = require('@northscaler/mutrait')

const { Acl, StaticAccessControlStrategy, PrimitiveAction } = require('@northscaler/acl')
const GRANT = StaticAccessControlStrategy.GRANT
const DENY = StaticAccessControlStrategy.DENY
const SECURE = PrimitiveAction.SECURE

const AuthorizationError = require('./AuthorizationError')

/**
 * The Securable trait.
 * This trait enables an expressing class to secure itself via an ACL.
 * @mixin
 * @type {TraitFunction}
 */
const Securable = Trait(s => class extends s {
  /**
   * Returns whether or not this securable is currently secured.
   * @memberof Securable
   * @instance
   */
  get secured () {
    return !!this._acl
  }

  /**
   * Determines whether the given principal can take all of the given actions against this securable.
   *
   * @param {object} arg The argument to be deconstructed.
   * @param {object[]} arg.principals The principals being tested for access control.
   * @param {object[]} arg.actions The actions being being tested for access control.
   * @param {*} [arg.data] Optional, arbitrary data that may be used to make an access control decision.
   * @memberof Securable
   * @instance
   */
  grants ({ principals, actions, data }) {
    return !this.secured || this._acl.grants({ principals, actions, securable: this, data })
  }

  /**
   * Determines whether the given principal is explicitly denied from taking any of the given actions against this securable.
   *
   * @param {object} arg The argument to be deconstructed.
   * @param {object[]} arg.principals The principals being tested for access control.
   * @param {object[]} arg.actions The actions being being tested for access control.
   * @param {*} [arg.data] Optional, arbitrary data that may be used to make an access control decision.
   * @memberof Securable
   * @instance
   */
  denies ({ principals, actions, data }) {
    return this.secured && this._acl.denies({ principals, actions, securable: this, data })
  }

  /**
   * Cause this securable to grant to the given principal the given action.
   *
   * Note: The principal must already be granted the right to secure this securable, unless this securable is not yet secured.
   *
   * @param {object} arg The argument to be deconstructed.
   * @param {object} arg.principal The principal being granted the ability to take `action`.
   * @param {object} arg.action The action being granted.
   * @param {object} [arg.securor=null] The securor of this `Securable`; if `null`, `principal` is used.
   * @memberof Securable
   * @instance
   */
  grant ({ principal, action, securor }) {
    return this.secure({ principal, action, strategy: GRANT, securor })
  }

  /**
   * Cause this securable to no longer grant to the given principal the given action.
   *
   * Note: The securor must already be granted the right to secure this securable, unless this securable is not yet secured.
   *
   * @param {object} arg The argument to be deconstructed.
   * @param {object} arg.principal The principal being ungranted the given `action`.
   * @param {object} arg.action The action being ungranted.
   * @param {object} [arg.securor=null] The securor of this `Securable`; if `null`, `principal` is used.
   * @memberof Securable
   * @instance
   */
  ungrant ({ principal, action, securor }) {
    if (!this.secured) return this

    return this.unsecure({ principal, action, strategy: GRANT, securor })
  }

  /**
   * Cause this securable to explicitly deny from the given principal the ability to take given action.
   *
   * Note: The securor must already be granted the right to secure this securable, unless this securable is not yet secured.
   *
   * @param {object} arg The argument to be deconstructed.
   * @param {object} arg.principal The principal being denied the given `action`.
   * @param {object} arg.action The action being denied.
   * @param {object} [arg.securor=null] The securor of this `Securable`; if `null`, `principal` is used.
   * @memberof Securable
   * @instance
   */
  deny ({ principal, action, securor }) {
    return this.secure({ principal, action, strategy: DENY, securor })
  }

  /**
   * Cause this securable to no longer explicitly deny from the given principal the ability to take given action.
   *
   * Note: The securor must already be granted the right to secure this securable, unless this securable is not yet secured.
   *
   * @param {object} arg The argument to be deconstructed.
   * @param {object} arg.principal The principal being undenied the given `action`.
   * @param {object} arg.action The action being undenied.
   * @param {object} [arg.securor=null] The securor of this `Securable`; if `null`, `principal` is used.
   * @memberof Securable
   * @instance
   */
  undeny ({ principal, action, securor }) {
    if (!this.secured) return this

    return this.unsecure({ principal, action, strategy: DENY, securor })
  }

  /**
   * Cause this securable to secure itself with the given security strategy to be used with the given principal for the given action.
   *
   * Note: The securor must already be granted the right to secure this securable, unless this securable is not yet secured.
   *
   * @param {object} arg The argument to be deconstructed.
   * @param {AccessControlStrategy} arg.strategy The access control decision functions.
   * @param {object} arg.principal The principal being granted or denied the given `action`.
   * @param {object} arg.action The action being granted or denied.
   * @param {object} [arg.securor=null] The securor of this `Securable`; if `null`, `principal` is used.
   * @memberof Securable
   * @instance
   */
  secure ({ strategy, principal, action, securor }) {
    return this._secure({ strategy, principal, action, securor, add: true })
  }

  /**
   * Cause this securable to no longer secure itself with the given security strategy with the given principal for the given action.
   *
   * Note: The securor must already be granted the right to secure this securable, unless this securable is not yet secured.
   *
   * @param {AccessControlStrategy} arg.strategy The access control decision functions.
   * @param {object} arg.principal The principal being granted or denied the given `action`.
   * @param {object} arg.action The action being granted or denied.
   * @param {object} [arg.securor=null] The securor of this `Securable`; if `null`, `principal` is used.
   * @memberof Securable
   * @instance
   */
  unsecure ({ strategy, principal, action, securor }) {
    if (!this.secured) return this

    return this._secure({ strategy, principal, action, securor, add: false })
  }

  /**
   * @param {object} arg The argument to deconstruct.
   * @param {AccessControlStrategy} arg.strategy The access control decision functions.
   * @param {object} arg.principal The principal being granted or denied the given `action`.
   * @param {object} arg.action The action being granted or denied.
   * @param {object} [arg.securor=null] The securor of this `Securable`; if `null`, `principal` is used.
   * @param {boolean} [arg.add] Whether we're adding or removing an entry from this `Securable`'s `Acl`.
   * @private
   * @memberof Securable
   * @instance
   */
  _secure ({ strategy, principal, action, securor = null, add = true }) {
    if (!this.secured) {
      this._ensureAcl()._secure({ strategy: GRANT, principal: securor || principal, action: SECURE, add: true })
    } else {
      this._authorizeSecurabilityBy(securor || principal)
    }
    this._acl._secure({ strategy, principal, action, add })

    return this
  }

  /**
   * Returns a non-null array reference of this securable's `Acl`.
   * If it doesn't exist, it's created.
   *
   * @return {Acl}
   * @private
   * @memberof Securable
   * @instance
   */
  _ensureAcl () {
    return (this._acl = this._acl || new Acl())
  }

  /**
   * Throws if this securable cannot be secured by the given principal.
   *
   * @param principal
   * @private
   * @memberof Securable
   * @instance
   */
  _authorizeSecurabilityBy (principal) {
    if (this.secured && !this.grants({ principals: principal, actions: SECURE })) {
      throw new AuthorizationError({ principal, action: SECURE })
    }
  }
})

module.exports = Securable
