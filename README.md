# securable-trait

This trait allows an object to secure itself, so that you can ask questions like "Can Sally read Bob's account balance?" or "Can bank teller John close account #123?"

The primary export of this module is a trait called `Securable`, which you can have your class(es) express.
See our [`@northscaler/mutrait`](https://npmjs.com/package/@northscaler/mutrait) package for more information, including full trait support in JavaScript.

## TL;DR

File `Account.js`:

```js
const { traits } = require('@northscaler/mutrait')
const { Securable } = require('@northscaler/securable-trait')

class Account extends traits(Securable) {
  constructor (balance = 0, openedAt = new Date()) {
    super(balance, openedAt)
    this._balance = balance
    this.openedAt = openedAt
    this.closedAt = null
  }

  get balance () { return this._balance }
  deposit (amount) { this._balance += amount } 
  withdraw (amount) { this._balance -= amount }
  close (at = new Date()) { this.closedAt = at }
  get open () { return !this.closed }
  get closed () { return !!this.closedAt }
}

module.exports = Account
```

File `index.js`:

```js
const Account = require('./Account')

const sally = 'sally'
const keith = 'keith'
const acct = new Account()

console.log(acct.secured) // false
console.log(acct.grants({ principals: sally, actions: 'get balance' })) // true
console.log(acct.grants({ principals: sally, actions: 'close' }))       // true
console.log(acct.grants({ principals: keith, actions: 'get balance' })) // true
console.log(acct.grants({ principals: keith, actions: 'close' }))       // true

acct.grant({ principal: sally, action: 'get balance' })
acct.grant({ principal: sally, action: 'close' })

console.log(acct.secured) // true

console.log(acct.grants({ principals: sally, actions: 'get balance' })) // true
console.log(acct.grants({ principals: keith, actions: 'close' }))       // false
console.log(acct.grants({ principals: sally, actions: 'get balance' })) // true
console.log(acct.grants({ principals: keith, actions: 'close' }))       // false
```

## Security via aspect-oriented programming (AOP)

When you combine this library with method interception via [`@northscaler/aspectify`](https://www.npmjs.com/package/@northscaler/aspectify) and with `ClsHookedContext` or `ZoneJsContext` from [`@northscaler/continuation-local-storage`](https://www.npmjs.com/package/@northscaler/continuation-local-storage), you can completely isolate the crosscutting concern of security.

File `Secured.js`:

```js
const { Before } = require('@northscaler/aspectify')
const Context = require('@northscaler/continuation-local-storage/context/ClsHookedContext')

const secured = Before(({ thisJoinPoint }) => {
  if (!thisJoinPoint.thiz || thisJoinPoint?.thiz === thisJoinPoint?.clazz) {
    return // because we're in a static context or there's no securable to call securable.grants on
  }
    
  const token = Context().get('token')

  if (!thisJoinPoint.thiz.grants({
    principals: token.principal,
    actions: thisJoinPoint.fullName
  })) {
    const e = new Error(`E_UNAUTHORIZED`)
    e.principal = token.principal
    e.clazz = thisJoinPoint.clazz.constructor.name
    e.method = thisJoinPoint.fullName
    
    throw e
  }
})

module.exports = secured
```

File `Account.js`:

```js
const { traits } = require('@northscaler/mutrait')
const { Securable } = require('@northscaler/securable-trait')
const secured = require('./secured')

class Account extends traits(Securable) {
  constructor (balance = 0, openedAt = new Date()) {
    super(balance, openedAt)
    this._balance = balance
    this.openedAt = openedAt
    this.closedAt = null
  }

  @secured
  get balance () { return this._balance }

  @secured
  deposit (amount) { this._balance += amount } 

  @secured
  withdraw (amount) { this._balance -= amount }

  @secured
  close (at = new Date()) { this.closedAt = at }

  @secured
  get open () { return !this.closed }

  @secured
  get closed () { return !!this.closedAt }
}

module.exports = Account
``` 

## TODO
There's more to write here, but for now, see the [tests](`src/test/unit/Securable.spec.js`) for usage.

