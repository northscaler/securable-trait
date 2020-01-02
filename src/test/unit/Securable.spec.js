/* global describe,it */
'use strict'

const chai = require('chai')
chai.use(require('dirty-chai'))
const expect = chai.expect
const { traits } = require('@northscaler/mutrait')

const Securable = require('../../main/Securable')
const { PrimitiveAction } = require('@northscaler/acl')

const Identifiable = require('./Identifiable')

class SomeSecurable extends traits(Identifiable, Securable) {}

class SomePrincipal extends traits(Identifiable) {}

describe('Securable', () => {
  describe('simple grant/deny security', () => {
    it('should grant when granted', () => {
      const securor = new SomePrincipal()
      securor._id = 'securor'
      const p1 = new SomePrincipal()
      const p2 = new SomePrincipal()
      const s = new SomeSecurable()
      const a = PrimitiveAction.READ

      for (const p of [securor, p1, p2]) {
        expect(s.grants({ principals: p, actions: a })).to.be.true()
        expect(s.denies({ principals: p, actions: a })).to.be.false()
      }

      s.ungrant({ principal: p1, action: a, securor })

      expect(s.grants({ principals: securor, actions: PrimitiveAction.SECURE })).to.be.true()
      expect(s.grants({ principals: securor, actions: PrimitiveAction.READ })).to.be.true()
      expect(s.grants({ principals: p1, actions: a })).to.be.true()
      expect(s.grants({ principals: p1, actions: PrimitiveAction.SECURE })).to.be.true()
      expect(s.denies({ principals: p1, actions: a })).to.be.false()
      expect(s.grants({ principals: p2, actions: a })).to.be.true()
      expect(s.grants({ principals: p2, actions: PrimitiveAction.SECURE })).to.be.true()
      expect(s.denies({ principals: p2, actions: a })).to.be.false()

      s.grant({ principal: p1, action: a, securor })

      expect(s.grants({ principals: securor, actions: PrimitiveAction.SECURE })).to.be.true()
      expect(s.grants({ principals: securor, actions: PrimitiveAction.READ })).to.be.false()
      expect(s.grants({ principals: p1, actions: a })).to.be.true()
      expect(s.grants({ principals: p1, actions: PrimitiveAction.SECURE })).to.be.false()
      expect(s.denies({ principals: p1, actions: a })).to.be.false()
      expect(s.grants({ principals: p2, actions: a })).to.be.false()
      expect(s.grants({ principals: p2, actions: PrimitiveAction.SECURE })).to.be.false()
      expect(s.denies({ principals: p2, actions: a })).to.be.false()
    })

    it('should deny when denied', () => {
      const securor = new SomePrincipal()
      securor._id = 'securor'
      const p1 = new SomePrincipal()
      const p2 = new SomePrincipal()
      const s = new SomeSecurable()
      const a = PrimitiveAction.READ

      for (const p of [securor, p1, p2]) {
        expect(s.grants({ principals: p, actions: a })).to.be.true()
        expect(s.denies({ principals: p, actions: a })).to.be.false()
      }

      s.undeny({ principal: p1, action: a, securor })

      expect(s.grants({ principals: securor, actions: PrimitiveAction.SECURE })).to.be.true()
      expect(s.grants({ principals: securor, actions: PrimitiveAction.READ })).to.be.true()
      expect(s.grants({ principals: p1, actions: a })).to.be.true()
      expect(s.grants({ principals: p1, actions: PrimitiveAction.SECURE })).to.be.true()
      expect(s.denies({ principals: p1, actions: a })).to.be.false()
      expect(s.grants({ principals: p2, actions: a })).to.be.true()
      expect(s.grants({ principals: p2, actions: PrimitiveAction.SECURE })).to.be.true()
      expect(s.denies({ principals: p2, actions: a })).to.be.false()

      s.deny({ principal: p1, action: a, securor })

      expect(s.grants({ principals: securor, actions: PrimitiveAction.SECURE })).to.be.true()
      expect(s.grants({ principals: securor, actions: PrimitiveAction.READ })).to.be.false()
      expect(s.grants({ principals: p1, actions: a })).to.be.false()
      expect(s.grants({ principals: p1, actions: PrimitiveAction.SECURE })).to.be.false()
      expect(s.denies({ principals: p1, actions: a })).to.be.true()
      expect(s.grants({ principals: p2, actions: a })).to.be.false()
      expect(s.grants({ principals: p2, actions: PrimitiveAction.SECURE })).to.be.false()
      expect(s.denies({ principals: p2, actions: a })).to.be.false()
    })

    it('should deny when denied even if permitted', () => {
      const p1 = new SomePrincipal()
      const s = new SomeSecurable()

      expect(s.grants({ principals: p1, actions: [PrimitiveAction.READ, PrimitiveAction.UPDATE] })).to.be.true()
      expect(s.denies({ principals: p1, actions: [PrimitiveAction.READ, PrimitiveAction.UPDATE] })).to.be.false()

      s.grant({ principal: p1, action: PrimitiveAction.READ })
      s.deny({ principal: p1, action: PrimitiveAction.UPDATE })

      expect(s.grants({ principals: p1, actions: PrimitiveAction.READ })).to.be.true()
      expect(s.grants({ principals: p1, actions: PrimitiveAction.UPDATE })).to.be.false()
      expect(s.denies({ principals: p1, actions: PrimitiveAction.READ })).to.be.false()
      expect(s.denies({ principals: p1, actions: PrimitiveAction.UPDATE })).to.be.true()
      expect(s.denies({ principals: p1, actions: [PrimitiveAction.READ, PrimitiveAction.UPDATE] })).to.be.true()
    })

    it('should grant all principals an action', () => {
      const p1 = new SomePrincipal()
      const p2 = new SomePrincipal()
      const s = new SomeSecurable()
      const a = PrimitiveAction.READ

      expect(s.grants({ principals: p1, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p1, actions: [a] })).to.be.false()
      expect(s.grants({ principals: p2, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p2, actions: [a] })).to.be.false()

      s.grant({ action: a })

      expect(s.grants({ principals: p1, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p1, actions: [a] })).to.be.false()
      expect(s.grants({ principals: p2, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p2, actions: [a] })).to.be.false()
    })

    it('should grant a principal all actions', () => {
      const p1 = new SomePrincipal()
      const p2 = new SomePrincipal()
      const s = new SomeSecurable()
      const a = 'foobar'

      expect(s.grants({ principals: p1, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p1, actions: [a] })).to.be.false()
      expect(s.grants({ principals: p2, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p2, actions: [a] })).to.be.false()

      s.grant({ principal: p1 })

      expect(s.grants({ principals: p1, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p1, actions: [a] })).to.be.false()
      expect(s.grants({ principals: p2, actions: [a] })).to.be.false()
      expect(s.denies({ principals: p2, actions: [a] })).to.be.false()
    })

    it('should grant all principals all actions', () => {
      const p1 = new SomePrincipal()
      const p2 = new SomePrincipal()
      const s = new SomeSecurable()
      const a = 'foobar'

      expect(s.grants({ principals: p1, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p1, actions: [a] })).to.be.false()
      expect(s.grants({ principals: p2, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p2, actions: [a] })).to.be.false()

      s.grant({})

      expect(s.grants({ principals: p1, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p1, actions: [a] })).to.be.false()
      expect(s.grants({ principals: p2, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p2, actions: [a] })).to.be.false()
    })

    it('should deny all principals an action', () => {
      const p1 = new SomePrincipal()
      const p2 = new SomePrincipal()
      const s = new SomeSecurable()
      const a = PrimitiveAction.READ

      expect(s.grants({ principals: p1, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p1, actions: [a] })).to.be.false()
      expect(s.grants({ principals: p2, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p2, actions: [a] })).to.be.false()

      s.deny({ action: a })

      expect(s.grants({ principals: p1, actions: [a] })).to.be.false()
      expect(s.denies({ principals: p1, actions: [a] })).to.be.true()
      expect(s.grants({ principals: p2, actions: [a] })).to.be.false()
      expect(s.denies({ principals: p2, actions: [a] })).to.be.true()
    })

    it('should deny a principal all actions', () => {
      const p1 = new SomePrincipal()
      const p2 = new SomePrincipal()
      const s = new SomeSecurable()
      const a = 'foobar'

      expect(s.grants({ principals: p1, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p1, actions: [a] })).to.be.false()
      expect(s.grants({ principals: p2, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p2, actions: [a] })).to.be.false()

      s.deny({ principal: p1 })

      expect(s.grants({ principals: p1, actions: [a] })).to.be.false()
      expect(s.denies({ principals: p1, actions: [a] })).to.be.true()
      expect(s.grants({ principals: p2, actions: [a] })).to.be.false()
      expect(s.denies({ principals: p2, actions: [a] })).to.be.false()
    })

    it('should deny all principals all actions', () => {
      const p1 = new SomePrincipal()
      const p2 = new SomePrincipal()
      const s = new SomeSecurable()
      const a = 'foobar'

      expect(s.grants({ principals: p1, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p1, actions: [a] })).to.be.false()
      expect(s.grants({ principals: p2, actions: [a] })).to.be.true()
      expect(s.denies({ principals: p2, actions: [a] })).to.be.false()

      s.deny({})

      expect(s.grants({ principals: p1, actions: [a] })).to.be.false()
      expect(s.denies({ principals: p1, actions: [a] })).to.be.true()
      expect(s.grants({ principals: p2, actions: [a] })).to.be.false()
      expect(s.denies({ principals: p2, actions: [a] })).to.be.true()
    })
  })

  describe('algorithmic security', () => {
    class Account extends traits(Identifiable, Securable) {
      constructor (initialBalance) {
        super(...arguments)
        this.balance = initialBalance
      }
    }

    class Teller extends traits(Identifiable) {}

    class Manager extends traits(Identifiable) {}

    class ManagersCanEditButTellersCanOnlyReadHighValueAccounts {
      constructor (threshold) {
        this.threshold = threshold
        this._deniedActions = [PrimitiveAction.UPDATE, PrimitiveAction.DELETE, PrimitiveAction.SECURE]
      }

      grants ({ principal }) {
        return principal instanceof Manager || principal instanceof Teller
      }

      denies ({ principal, action, securable: account }) {
        return principal instanceof Teller &&
          account.balance >= this.threshold &&
          this._deniedActions.includes(action)
      }
    }

    it('should work', () => {
      const threshold = 10000
      const strategy = new ManagersCanEditButTellersCanOnlyReadHighValueAccounts(threshold)
      const lo = new Account(threshold - 1)
      const hi = new Account(threshold + 1)
      const teller = new Teller()
      const manager = new Manager()
      const securor = new Manager()

      lo.secure({ strategy, securor })
      hi.secure({ strategy, securor })

      const instanceActions = [PrimitiveAction.READ, PrimitiveAction.UPDATE, PrimitiveAction.DELETE]

      expect(lo.grants({ principals: teller, actions: instanceActions })).to.be.true()
      expect(lo.denies({ principals: teller, actions: instanceActions })).to.be.false()
      expect(hi.grants({ principals: teller, actions: instanceActions })).to.be.false()
      expect(hi.denies({ principals: teller, actions: instanceActions })).to.be.true()

      expect(lo.grants({ principals: manager, actions: instanceActions })).to.be.true()
      expect(lo.denies({ principals: manager, actions: instanceActions })).to.be.false()
      expect(hi.grants({ principals: manager, actions: instanceActions })).to.be.true()
      expect(hi.denies({ principals: manager, actions: instanceActions })).to.be.false()
    })
  })
})
