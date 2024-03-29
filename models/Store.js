const mongoose = require('mongoose');
mongoose.Promise = global.Promise;
const slug = require('slugs');

const storeSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      trim: true,
      required: 'Please enter a store name'
    },
    slug: String,
    description: {
      type: String,
      trim: true
    },
    tags: [String],
    created: {
      type: Date,
      default: Date.now
    },
    location: {
      type: {
        type: String,
        default: 'Point'
      },
      coordinates: [{
        type: Number,
        required: 'You must supply coordinates!'
      }],
      address: {
        type: String,
        required: 'You must supply an address!'
      }
    },
    photo: String,
    author: {
      type: mongoose.Schema.ObjectId,
      ref: 'User',
      required: 'You must supply an author'
    }
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);


// define our indexes
storeSchema.index({
  name: 'text',
  description: 'text'
});

storeSchema.index({ location: '2dsphere' });


storeSchema.pre('save', async function(next) {
  if (!this.isModified('name')) {
    return next(); // skip it and stop this function from running
  }

  this.slug = slug(this.name);

  // TODO make more resilient so slugs are unique
  // find other stores that have a slug of bolu, bolu-1, bolu-2
  const slugRegEx = new RegExp(`^(${this.slug})((-[0-9]*$)?)$`, 'i');
  const storesWithSlug = await this.constructor.find({ slug: slugRegEx });
  if (storesWithSlug.length) {
    console.log(`length is ${storesWithSlug.length}`);
    this.slug = `${this.slug}-${storesWithSlug.length + 1}`;
  }
  next();
});


storeSchema.statics.getTagsList = function() {
  return this.aggregate([
    { $unwind: '$tags' },
    {
      $group: {
        _id: '$tags',
        count: { $sum: 1 }
      }
    },
    {
      $sort: { count: -1 }
    }
  ]);
};


storeSchema.statics.getTopStores = function() {
  return this.aggregate([
    // lookup stores and populate their reviews
    {
      $lookup: {
        from: 'reviews',
        localField: '_id',
        foreignField: 'store',
        as: 'reviews'
      }
    },
    // filter for only items that have 2 or more reviews
    {
      $match: {
        'reviews.1': { $exists: true }
      }
    },
    // Add the average reviews field
    {
      $addFields: {
        averageRating: { $avg: '$reviews.rating' }
      }
    },
    // sort it by our new field, highest reviews first
    {
      $sort: { averageRating: -1 }
    },
    // limit to at most 10
    { $limit: 10 }
  ]);
}


// find reviews where the stores._id property === reviews.store property
storeSchema.virtual('reviews', {
  ref: 'Review', // what model to link?
  localField: '_id', // which field on the Store?
  foreignField: 'store' // which field on the Review?
});


function autopopulate(next) {
  this.populate('reviews');
  next();
}

storeSchema.pre('find', autopopulate);
storeSchema.pre('find', autopopulate);


module.exports = mongoose.model('Store', storeSchema);