import { ObjectId } from "mongodb";
import type {
  Collection,
  DeleteResult,
  Document,
  Filter,
  FindOptions,
  InsertOneResult,
  OptionalUnlessRequiredId,
  UpdateFilter,
  UpdateOptions,
  UpdateResult,
  WithId,
} from "mongodb";

const normalizeId = (id: string | ObjectId): string | ObjectId => {
  if (id instanceof ObjectId) return id;
  return ObjectId.isValid(id) ? new ObjectId(id) : id;
};

export class BaseRepository<TDocument extends Document> {
  private readonly collectionFactory: () => Collection<TDocument>;

  constructor(collection: Collection<TDocument> | (() => Collection<TDocument>)) {
    this.collectionFactory =
      typeof collection === "function" ? (collection as () => Collection<TDocument>) : () => collection;
  }

  protected getCollection() {
    return this.collectionFactory();
  }

  async findById(id: string | ObjectId, options?: FindOptions<TDocument>) {
    return this.getCollection().findOne({ _id: normalizeId(id) } as Filter<TDocument>, options);
  }

  async findOne(filter: Filter<TDocument>, options?: FindOptions<TDocument>) {
    return this.getCollection().findOne(filter, options);
  }

  async findMany(filter: Filter<TDocument> = {} as Filter<TDocument>, options?: FindOptions<TDocument>) {
    return this.getCollection().find(filter, options).toArray();
  }

  async insertOne(doc: OptionalUnlessRequiredId<TDocument>): Promise<InsertOneResult<TDocument>> {
    return this.getCollection().insertOne(doc);
  }

  async updateOne(
    filter: Filter<TDocument>,
    update: UpdateFilter<TDocument>,
    options?: UpdateOptions,
  ): Promise<UpdateResult<TDocument>> {
    return this.getCollection().updateOne(filter, update, options);
  }

  async upsertOne(filter: Filter<TDocument>, update: UpdateFilter<TDocument>) {
    return this.getCollection().updateOne(filter, update, { upsert: true });
  }

  async deleteOne(filter: Filter<TDocument>): Promise<DeleteResult> {
    return this.getCollection().deleteOne(filter);
  }

  async count(filter: Filter<TDocument> = {} as Filter<TDocument>) {
    return this.getCollection().countDocuments(filter);
  }
}

export const createRepository = <TDocument extends Document>(
  collection: Collection<TDocument> | (() => Collection<TDocument>),
) =>
  new BaseRepository<TDocument>(collection);

export type Entity<TDocument extends Document> = WithId<TDocument>;
