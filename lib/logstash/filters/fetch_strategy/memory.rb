# encoding: utf-8
require "ipaddr"

module LogStash module Filters module FetchStrategy module Memory
  class Exact
    def initialize(dictionary)
      @dictionary = dictionary
    end

    def fetch(source, results)
      if @dictionary.include?(source)
        results[1] = LogStash::Util.deep_clone(@dictionary[source])
      else
        results[0] = false
      end
    end
  end

  class Cidr
    def initialize(dictionary)
        @keys_cidr = Hash.new()
        @dictionary = dictionary
        @dictionary.keys.each{|k| @keys_cidr[k] = IPAddr.new(k.strip)}
        #Sort dictionnary
        @keys_cidr = @keys_cidr.sort.to_h 
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
          if ip_hash[ip_array[i]].include?(ip)
              return ip_array[i]
          else
              comp_result = ip<=>ip_hash[ip_array[i]]
              if comp_result == 1
                  return binary_search_recursive(ip_hash[ip_array[i+1, last]], ip)
              else
                  return binary_search_recursive(ip_hash[ip_array[first, i]], ip)
              end
          end
      end
    end

    def fetch(source, results)
      begin
        if !(IPAddr.new(source) rescue nil).nil?  
          ip = IPAddr.new(source)
          key = binary_search_recursive(@keys_cidr, ip)
          if key.nil?
            results[0] = false
          else
            results[1] = LogStash::Util.deep_clone(@dictionary[key])
          end
        else
            results[0] = false
        end 
      end
    end
  end

  class ExactRegex
    def initialize(dictionary)
      @keys_regex = Hash.new()
      @dictionary = dictionary
      @dictionary.keys.each{|k| @keys_regex[k] = Regexp.new(k)}
    end

    def fetch(source, results)
      key = @dictionary.keys.detect{|k| source.match(@keys_regex[k])}
      if key.nil?
        results[0] = false
      else
        results[1] = LogStash::Util.deep_clone(@dictionary[key])
      end
    end
  end

  class RegexUnion
    def initialize(dictionary)
      @dictionary = dictionary
      @union_regex_keys = Regexp.union(@dictionary.keys)
    end

    def fetch(source, results)
      value = source.gsub(@union_regex_keys, @dictionary)
      if source == value
        results[0] = false
      else
        results[1] = LogStash::Util.deep_clone(value)
      end
    end
  end
end end end end


