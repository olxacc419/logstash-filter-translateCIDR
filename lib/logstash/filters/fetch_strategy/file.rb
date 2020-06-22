# encoding: utf-8
require "ipaddr"

module LogStash module Filters module FetchStrategy module File
  class Exact
    def initialize(dictionary, rw_lock)
      @dictionary = dictionary
      @read_lock = rw_lock.readLock
    end

    def dictionary_updated
    end

    def fetch(source, results)
      @read_lock.lock
      begin
        if @dictionary.include?(source)
          results[1] = LogStash::Util.deep_clone(@dictionary[source])
        else
          results[0] = false
        end
      ensure
        @read_lock.unlock
      end
    end
  end

  class Cidr
	
    def initialize(dictionary, rw_lock)
      @keys_cidr = Hash.new()
      @dictionary = dictionary
      @read_lock = rw_lock.readLock
      #Sort dictionnary
      #@keys_cidr = @keys_cidr.sort.to_h
    end

    def dictionary_updated
      @keys_cidr.clear
      @dictionary.keys.each{|k| @keys_cidr[k] = IPAddr.new(k)}
      #Sort dictionnary by value
      @keys_cidr = @keys_cidr.sort_by {|k,v| v}.to_h
    end

    def binary_search_recursive(ip_hash, ip)
      if ip_hash.nil?
        return nil
      end 
      ip_array = ip_hash.keys
      first = 0
      last = ip_array.length - 1
  
      if ip_array.length == 0
          #Not found
          return nil
      else
          i = (first + last) / 2
		  if ip_array[i].nil? || ip_hash[ip_array[i]].nil? 
			  return nil
          elsif ip_hash[ip_array[i]].include?(ip)
              return ip_array[i]
          else
              comp_result = ip<=>ip_hash[ip_array[i]]
              sub_hash_key = Hash.new()
              if comp_result == 1
                  ip_array[i+1, last].each { |k| sub_hash_key[k] = ip_hash[k] }
                  #return binary_search_recursive(ip_hash[ip_array[i+1, last]], ip)
              else
                  ip_array[first, i].each { |k| sub_hash_key[k] = ip_hash[k] }
                  #return binary_search_recursive(ip_hash[ip_array[first, i]], ip)
              end
              return binary_search_recursive(sub_hash_key, ip)
          end
      end
    end

    def fetch(source, results)
      @read_lock.lock
      begin
        if !(IPAddr.new(source.strip) rescue nil).nil? 
          ip = IPAddr.new(source.strip)
          #key = @dictionary.keys.detect{|k| @keys_cidr[k].include?(ip)}
          key = binary_search_recursive(@keys_cidr, ip)
          if key.nil?
            results[0] = false
          else
            results[1] = LogStash::Util.deep_clone(@dictionary[key])
          end
        else
          results[0] = false
        end
      ensure
        @read_lock.unlock
      end
    end
  end

  class ExactRegex
    def initialize(dictionary, rw_lock)
      @keys_regex = Hash.new()
      @dictionary = dictionary
      @read_lock = rw_lock.readLock
    end

    def dictionary_updated
      @keys_regex.clear
      # rebuilding the regex map is time expensive
      # 100 000 keys takes 0.5 seconds on a high spec Macbook Pro
      # at least we are not doing it for every event like before
      @dictionary.keys.each{|k| @keys_regex[k] = Regexp.new(k)}
    end

    def fetch(source, results)
      @read_lock.lock
      begin
        key = @dictionary.keys.detect{|k| source.match(@keys_regex[k])}
        if key.nil?
          results[0] = false
        else
          results[1] = LogStash::Util.deep_clone(@dictionary[key])
        end
      ensure
        @read_lock.unlock
      end
    end
  end

  class RegexUnion
    def initialize(dictionary, rw_lock)
      @dictionary = dictionary
      @read_lock = rw_lock.readLock
    end

    def dictionary_updated
      @union_regex_keys = Regexp.union(@dictionary.keys)
    end

    def fetch(source, results)
      @read_lock.lock
      begin
        value = source.gsub(@union_regex_keys, @dictionary)
        if source == value
          results[0] = false
        else
          results[1] = LogStash::Util.deep_clone(value)
        end
      ensure
        @read_lock.unlock
      end
    end
  end
end end end end
