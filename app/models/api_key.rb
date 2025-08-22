# == Schema Information
#
# Table name: api_keys
#
#  id               :bigint           not null, primary key
#  may_impersonate  :boolean
#  name             :string
#  pii              :boolean
#  revoked_at       :datetime
#  token_bidx       :string
#  token_ciphertext :text
#  created_at       :datetime         not null
#  updated_at       :datetime         not null
#  user_id          :bigint           not null
#
# Indexes
#
#  index_api_keys_on_token_bidx  (token_bidx) UNIQUE
#  index_api_keys_on_user_id     (user_id)
#
# Foreign Keys
#
#  fk_rails_...  (user_id => users.id)
#
class APIKey < ApplicationRecord
  belongs_to :user

  validates :token, presence: true, uniqueness: true
  validate :impersonation_requires_admin, if: :may_impersonate?

  scope :not_revoked, -> { where(revoked_at: nil).or(where(revoked_at: Time.now..)) }
  scope :accessible, -> { not_revoked }

  before_validation :generate_token, on: :create

  TOKEN = ExternalToken.new("api")

  has_encrypted :token
  blind_index :token

  def pretty_name = "#{user.username}@#{name}"

  def revoke! = update!(revoked_at: Time.now)

  def revoked? = revoked_at.present?

  def active? = !revoked?

  def abbreviated = "#{token[..15]}.....#{token[-5..]}"

  private

  def generate_token
    self.token ||= TOKEN.generate
  end

  def impersonation_requires_admin
    unless user&.admin?
      errors.add(:may_impersonate, "can only be enabled by admin users")
    end
  end
end
