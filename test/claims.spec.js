process.env.NODE_ENV = 'test'

let mongo = require('mongodb')
  , chai = require('chai')
  , chaiHttp = require('chai-http')
  , server = require('../server')
  , should = chai.should()
  , Sinon = require('sinon')
  , DB = require('./db')
  , Mailgun = require('mailgun-js')
  , crypto = require('crypto')
  , sandbox = Sinon.createSandbox()
  , mailgunSendSpy = sandbox.stub().yields(null, {success: true})

chai.use(chaiHttp)

describe('Claims', () => {
  var token, claim_ids, update_claim_id, updated_claim, githubtoken, update_github_claim_id
  var user = {
    email: "person@example.com",
    password: "testpass123"
  }

  beforeEach('setup Sinon sandbox', () => {
    sandbox.stub(Mailgun({ apiKey: 'foo', domain: 'bar' }).Mailgun.prototype, 'messages').returns({
      send: mailgunSendSpy
    })
  })

  afterEach('restore Sinon sandbox', () => {
    sandbox.restore()
  })

  before('connect to the database', (done) => {
    DB.connect(done)
  })

  before('sign up a user', (done) => {
    item = Object.assign({}, user, {
      name: "Dummy"
    })
    chai.request(server)
      .post('/signup')
      .send(item)
      .end((err, res) => {
        res.should.have.status(200)
        token = res.body.token
        done()
      })
  })

  before('approve and verify the user', (done) => {
    users = DB.getDB().collection('users')
    users.update({email: user.email},
      { $set: { approved: true, verified: true } },
      { safe: true },
      (err, res) => {
        done()
      })
  })

  before('try to login the user', (done) => {
    chai.request(server)
      .post('/login')
      .send(user)
      .end((err, res) => {
        res.should.have.status(200)
        token = res.body.token
        done()
      })
  })

  describe('/POST claims', () => {

    it('should add to database and return 200', (done) => {
      let claim = {
        title: 'This is claim',
        desc: 'A description',
        proof: 'Proof of the claim',
      }

      chai.request(server)
        .post('/claims')
        .set('Authorization', 'Bearer ' + token)
        .send(claim)
        .end((err, res) => {
          res.body.should.be.a('object')
          res.should.have.status(200)
          claim_id.push(res.body.claim[0]._id)
          done()
        })
    })


    it('should return 401 if not logged in', (done) => {
      let claim = {
        title: 'This is claim',
        desc: 'A description',
        proof: 'Proof of the claim'
      }

      chai.request(server)
        .post('/claims')
        .send(claim)
        .end((err, res) => {
          res.should.have.status(401)
          res.body.should.be.a('object')
          res.body.message.should.equal('Authentication failed')
          res.body.success.should.equal(false)
          done()
        })
    })

    it('should return 422 if any of the arguments is missing', (done) => {
      let claim = {
        title: 'This is claim',
        desc: 'A description',
      }
      chai.request(server)
        .post('/claims')
        .send(claim)
        .end((err, res) => {
          res.should.have.status(422)
          done()
        })
    })

    it('should parse proof and send an email for github repo conformation claim', done => {
      let claim = {
        title: 'githubRepoOwnership',
        desc: 'A description',
        proof: 'https://github.com/user1'
      }
      chai.request(server)
        .post('/claims')
        .set('Authorization', 'Bearer ' + token)
        .send(claim)
        .end((err, res) => {
          res.should.have.status(200)
          res.body.should.include({proof: 'user1'})
          res.body.should.have.property('githubtoken')
          claim_id.push(res.body.claim[0]._id)
          mailgunSendSpy.calledOnce.should.be.equal(true)
          done()
        })
    })

    it('should return 422 for invalid proof format for github repo conformation claim', done => {
      let claim = {
        title: 'githubRepoOwnership',
        desc: 'A description',
        proof: 'https://github.com/user1/repo'
      }
      chai.request(server)
        .post('/claims')
        .set('Authorization', 'Bearer ' + token)
        .send(claim)
        .end((err, res) => {
          res.should.have.status(422)
          res.body.success.should.equal(false)
          res.body.message.should.equal('Invalid proof format for Github account verification claim')
          mailgunSendSpy.calledOnce.should.be.equal(false)
          done()
        })
    })

    it('should return 422 for github repo conformation claim with same proof as already existed', done => {
      let claim = {
        title: 'githubRepoOwnership',
        desc: 'A description',
        proof: 'https://github.com/user1'
      }
      chai.request(server)
        .post('/claims')
        .set('Authorization', 'Bearer ' + token)
        .send(claim)
        .end((err, res) => {
          res.should.have.status(422)
          res.body.success.should.equal(false)
          res.body.message.should.equal('There is already a claim request for this proof')
          mailgunSendSpy.calledOnce.should.be.equal(false)
          done()
        })
    })

    it('should treat proof of github repo conformation claim ending with "/" same as without ending "/"', done => {
      let claim = {
        title: 'githubRepoOwnership',
        desc: 'A description',
        proof: 'https://github.com/user1/'
      }
      chai.request(server)
        .post('/claims')
        .set('Authorization', 'Bearer ' + token)
        .send(claim)
        .end((err, res) => {
          res.should.have.status(422)
          res.body.success.should.equal(false)
          res.body.message.should.equal('There is already a claim request for this proof')
          mailgunSendSpy.calledOnce.should.be.equal(false)
          done()
        })
    })

    it('should successfully add another github repo conformation claim for a new github account', done => {
      let claim = {
        title: 'githubRepoOwnership',
        desc: 'A description',
        proof: 'https://github.com/user2'
      }
      chai.request(server)
        .post('/claims')
        .set('Authorization', 'Bearer ' + token)
        .send(claim)
        .end((err, res) => {
          res.should.have.status(200)
          res.body.should.include({proof: 'user1'})
          res.body.should.have.nested.property('githubtoken')
          githubtoken = res.body.githubtoken
          update_github_claim_id = res.body.claim[0]._id
          claim_id.push(res.body.claim[0]._id)
          mailgunSendSpy.calledOnce.should.be.equal(true)
          done()
        })
    })
  })

  after('posting claims, remove it', (done) => {
    claims = DB.getDB().collection('claims')
    Promise.all(claim_ids.map(claim_id =>
      claims.remove({_id: mongo.ObjectID(claim_id)})
    )).then(done)
  })

  before('updating claim, create a new one', (done) => {
    let claim = {
      title: 'This is claim',
      desc: 'A description',
      proof: 'Proof of the claim',
    }

    chai.request(server)
      .post('/claims')
      .set('Authorization', 'Bearer ' + token)
      .send(claim)
      .end((err, res) => {
        res.body.should.be.a('object')
        res.should.have.status(200)
        update_claim_id = res.body.claim[0]._id
        done()
      })
  })

  describe('POST /updateclaim', () => {
    it('should return 200 if all goes fine', (done) => {
      updated_claim = {
        title: 'An updated title',
        desc: 'An updated description',
        proof: 'We are changing the proof to update it',
        claim_id: update_claim_id
      }
      chai.request(server)
        .post('/updateclaim')
        .set('Authorization', 'Bearer ' + token)
        .send(claim)
        .end((err, res) => {
          res.body.should.be.a('object')
          res.should.have.status(200)
          res.body.claim[0].proof.should.equal(updated_claim.proof)
          done()
        })
    })

    it('should return 422 if any of the arguments is missing', (done) => {
      updated_claim = {
        title: 'An updated title',
        desc: 'An updated description',
        proof: 'We are changing the proof to update it',
        claim_id: update_claim_id
      }
      chai.request(server)
        .post('/updateclaim')
        .set('Authorization', 'Bearer ' + token)
        .send(claim)
        .end((err, res) => {
          res.body.should.be.a('object')
          res.should.have.status(422)
          done()
        })
    })

    it('should modify proof with parsed value for github account verification claim', done => {
      updated_claim = {
        title: 'githubRepoOwnership',
        desc: 'An updated description',
        proof: 'https://github.com/user3',
        claim_id: update_github_claim_id
      }
      chai.request(server)
        .post('/updateclaim')
        .set('Authorization', 'Bearer ' + token)
        .send(claim)
        .end((err, res) => {
          res.body.should.be.a('object')
          res.should.have.status(200)
          res.body.claim[0].proof.should.equal('user3')
          done()
        })
    })

    it('should return 422 for invalid proof format for github repo conformation claim', done => {
      let claim = {
        title: 'githubRepoOwnership',
        desc: 'A description',
        proof: 'https://github.com/user3/repo',
        claim_id: update_github_claim_id
      }
      chai.request(server)
        .post('/updateclaim')
        .set('Authorization', 'Bearer ' + token)
        .send(claim)
        .end((err, res) => {
          res.should.have.status(422)
          res.body.success.should.equal(false)
          res.body.message.should.equal('Invalid proof format for Github account verification claim')
          done()
        })
    })

    it('should return 422 on attempt to change proof for github repo conformation claim on some that already existed', done => {
      let claim = {
        title: 'githubRepoOwnership',
        desc: 'A description',
        proof: 'https://github.com/user1'
      }
      chai.request(server)
        .post('/updateclaim')
        .set('Authorization', 'Bearer ' + token)
        .send(claim)
        .end((err, res) => {
          res.should.have.status(422)
          res.body.success.should.equal(false)
          res.body.message.should.equal('You can`t have two claims for single github account verification')
          done()
        })
    })

    it('should treat proof of github repo conformation claim ending with "/" same as without ending "/"', done => {
      let claim = {
        title: 'githubRepoOwnership',
        desc: 'A description',
        proof: 'https://github.com/user1/'
      }
      chai.request(server)
        .post('/updateclaim')
        .set('Authorization', 'Bearer ' + token)
        .send(claim)
        .end((err, res) => {
          res.should.have.status(422)
          res.body.success.should.equal(false)
          res.body.message.should.equal('You can`t have two claims for single github account verification')
          done()
        })
    })

    it('should return 401 if user is not logged in')
  })

  describe('GET /getclaims', () => {
    it('should return 200 along with claim data', (done) => {
      chai.request(server)
        .get('/getclaims')
        .set('Authorization', 'Bearer ' + token)
        .send({claim_id: update_claim_id})
        .end((err, res) => {
          res.body.should.be.a('object')
          res.should.have.status(200)
          res.body.claim[0].proof.should.equal(updated_claim.proof)
          done()
        })
    })

    it('should return 404 no claim is found', (done) => {

      chai.request(server)
        .get('/getclaims')
        .set('Authorization', 'Bearer ' + token)
        .send({claim_id: '59a6ad282e7e26a8b402junk'})
        .end((err, res) => {
          res.body.should.be.a('object')
          res.should.have.status(404)
          done()
        })
    })
  })

  after('all tests, clear everything', (done) => {
    DB.drop(done)
  })

})